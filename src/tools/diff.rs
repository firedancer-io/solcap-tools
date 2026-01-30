use crate::reader::{AgaveBhdReaderError, SolcapData, SolcapReaderError, read_account_data};
use crate::reader::structures::AccountUpdate;
use crate::utils::spinner::Spinner;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::fs;
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug)]
pub enum DiffError {
    SolcapError(SolcapReaderError),
    AgaveError(AgaveBhdReaderError),
    IoError(std::io::Error),
    PathNotFound(String),
}

impl From<SolcapReaderError> for DiffError {
    fn from(err: SolcapReaderError) -> Self { DiffError::SolcapError(err) }
}

impl From<AgaveBhdReaderError> for DiffError {
    fn from(err: AgaveBhdReaderError) -> Self { DiffError::AgaveError(err) }
}

impl From<std::io::Error> for DiffError {
    fn from(err: std::io::Error) -> Self { DiffError::IoError(err) }
}

/* Helper to print a diff line */
fn print_diff<T: std::fmt::Display>(label: &str, v1: T, v2: T) {
    println!("  {}:", label);
    println!("    \x1b[31m- 1: {}\x1b[0m", v1);
    println!("    \x1b[32m+ 2: {}\x1b[0m", v2);
}

/* Format bytes as hex */
fn hex(data: &[u8]) -> String {
    if data.is_empty() { return "(empty)".to_string(); }
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/* Format pubkey/hash as base58 */
fn b58(key: &[u8; 32]) -> String { bs58::encode(key).into_string() }

/* Parse path into SolcapData */
fn parse_path<P: AsRef<Path>>(path: P, name: &str) -> Result<SolcapData, DiffError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(DiffError::PathNotFound(format!("Path does not exist: {}", path.display())));
    }

    let spinner = Spinner::new(&format!("\x1b[1mIngesting {}\x1b[0m \x1b[2m{}\x1b[0m", name, path.display()));
    
    let data = if path.is_dir() {
        use crate::reader::agave_bhd_reader::AgaveBhdReader;
        AgaveBhdReader::from_directory(path)?.parse_directory()?
    } else {
        use crate::reader::solcap_reader::SolcapReader;
        SolcapReader::from_file(path)?.parse_file()?
    };

    spinner.finish_with_lines(vec![&format!(
        "    Slots: {} - {} \x1b[2m({} slots, {} accounts)\x1b[0m",
        data.lowest_slot, data.highest_slot, data.slot_count(), data.total_account_updates_final()
    )]);
    Ok(data)
}

/* Load all account data for a slot - OPTIMIZED for bank_hash_details 
   Groups accounts by source file and loads each file only once */
fn load_slot_data(
    keys: &HashSet<[u8; 32]>, 
    updates: &HashMap<[u8; 32], AccountUpdate>, 
    path: &PathBuf
) -> HashMap<[u8; 32], Vec<u8>> {
    let mut cache = HashMap::new();
    
    /* Group accounts by source file */
    let mut by_file: HashMap<Option<String>, Vec<[u8; 32]>> = HashMap::new();
    for key in keys {
        if let Some(acc) = updates.get(key) {
            by_file.entry(acc.file.clone()).or_default().push(*key);
        }
    }
    
    for (file_opt, account_keys) in by_file {
        if let Some(file_path) = file_opt {
            /* Bank hash details - load ALL accounts from this JSON file at once */
            if let Ok(file_data) = load_bhd_file_data(&file_path, &account_keys, updates) {
                cache.extend(file_data);
            }
        } else {
            /* Solcap file - read each account (efficient with offset seeks) */
            for key in account_keys {
                if let Some(acc) = updates.get(&key) {
                    if let Ok(data) = read_account_data(path, acc) {
                        cache.insert(key, data);
                    }
                }
            }
        }
    }
    
    cache
}

/* Load multiple accounts from a single bank_hash_details JSON file (batch operation) */
fn load_bhd_file_data(
    file_path: &str,
    keys: &[[u8; 32]],
    updates: &HashMap<[u8; 32], AccountUpdate>,
) -> Result<HashMap<[u8; 32], Vec<u8>>, std::io::Error> {
    /* Read and parse JSON file ONCE */
    let contents = fs::read_to_string(file_path)?;
    let bhd: crate::reader::agave_bhd_reader::AgaveBankHashDetails = 
        serde_json::from_str(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    
    /* Build set of target keys for fast lookup */
    let target_keys: HashSet<String> = keys.iter().map(|k| b58(k)).collect();
    
    /* Find target slot from first account */
    let target_slot = keys.first().and_then(|k| updates.get(k)).map(|acc| acc.slot);
    
    let mut result = HashMap::new();
    
    /* Extract matching accounts in single pass */
    for entry in bhd.bank_hash_details {
        if Some(entry.slot) == target_slot {
            for account in &entry.accounts {
                if target_keys.contains(&account.pubkey) {
                    if let Ok(data) = general_purpose::STANDARD.decode(&account.data) {
                        if let Ok(key_bytes) = bs58::decode(&account.pubkey).into_vec() {
                            if key_bytes.len() == 32 {
                                let mut key = [0u8; 32];
                                key.copy_from_slice(&key_bytes);
                                result.insert(key, data);
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(result)
}

/* Main diff function */
pub fn diff_solcap<P1: AsRef<Path>, P2: AsRef<Path>>(
    path1: P1,
    path2: P2,
    verbosity: u8,
    start_slot: Option<u32>,
    end_slot: Option<u32>,
) -> Result<(), DiffError> {
    println!("\n         \x1b[1;33mSolcap Diff\x1b[0m\n─────────────────────────────\n");

    let data1 = parse_path(&path1, "Source 1")?;
    let data2 = parse_path(&path2, "Source 2")?;
    let path1 = path1.as_ref().to_path_buf();
    let path2 = path2.as_ref().to_path_buf();

    /* Find common slots */
    let slots1: HashSet<u32> = data1.slot_account_updates_final.keys().copied().collect();
    let slots2: HashSet<u32> = data2.slot_account_updates_final.keys().copied().collect();
    let mut common: Vec<u32> = slots1.intersection(&slots2)
        .copied()
        .filter(|s| start_slot.map_or(true, |st| *s >= st) && end_slot.map_or(true, |en| *s <= en))
        .collect();
    common.sort_unstable();

    if common.is_empty() {
        println!("\nNo common slots found.");
        return Ok(());
    }

    println!("\nComparing {} common slots\n{}", common.len(), "=".repeat(80));

    let mut diff_slots = 0;
    let mut diff_accounts = 0;

    for slot in common {
        let (has_diff, n_accounts) = diff_slot(slot, &data1, &data2, verbosity, &path1, &path2);
        if has_diff { 
            diff_slots += 1; 
        } else {
            println!("\nSlot {} - \x1b[32mMATCH\x1b[0m", slot);
        }
        diff_accounts += n_accounts;
    }

    println!("\n{}\nSummary:\n  Differing slots: {}\n  Differing accounts: {}", "=".repeat(80), diff_slots, diff_accounts);
    Ok(())
}

/* Diff a single slot */
fn diff_slot(slot: u32, d1: &SolcapData, d2: &SolcapData, v: u8, p1: &PathBuf, p2: &PathBuf) -> (bool, usize) {
    let mut has_diff = false;
    let diff_accounts;

    /* v1+: Bank preimage */
    if v >= 1 {
        if let (Some(pre1), Some(pre2)) = (d1.get_bank_preimage(slot), d2.get_bank_preimage(slot)) {
            if pre1.bank_hash.hash != pre2.bank_hash.hash {
                if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                print_diff("Bank Hash", b58(&pre1.bank_hash.hash), b58(&pre2.bank_hash.hash));
            }
            
            /* v2+: Full preimage */
            if v >= 2 {
                if pre1.prev_bank_hash.hash != pre2.prev_bank_hash.hash {
                    if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                    print_diff("Prev Bank Hash", b58(&pre1.prev_bank_hash.hash), b58(&pre2.prev_bank_hash.hash));
                }
                if pre1.accounts_lt_hash_checksum.hash != pre2.accounts_lt_hash_checksum.hash {
                    if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                    print_diff("Accounts LT Hash", b58(&pre1.accounts_lt_hash_checksum.hash), b58(&pre2.accounts_lt_hash_checksum.hash));
                }
                if pre1.poh_hash.hash != pre2.poh_hash.hash {
                    if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                    print_diff("PoH Hash", b58(&pre1.poh_hash.hash), b58(&pre2.poh_hash.hash));
                }
                let (s1, s2) = (pre1.signature_cnt, pre2.signature_cnt);
                if s1 != s2 {
                    if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                    print_diff("Signature Count", s1, s2);
                }
            }
        }
    }

    /* v3+: Account comparison */
    let mut n_diff_accounts = 0;
    if v >= 3 {
        let u1 = d1.get_account_updates_final(slot);
        let u2 = d2.get_account_updates_final(slot);
        
        if let (Some(u1), Some(u2)) = (u1, u2) {
            let k1: HashSet<[u8; 32]> = u1.keys().copied().collect();
            let k2: HashSet<[u8; 32]> = u2.keys().copied().collect();
            let common: HashSet<[u8; 32]> = k1.intersection(&k2).copied().collect();
            let only1: Vec<_> = k1.difference(&k2).collect();
            let only2: Vec<_> = k2.difference(&k1).collect();

            /* Accounts only in source 1 */
            if !only1.is_empty() {
                if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                println!("  Accounts only in Source 1: {}", only1.len());
                for k in &only1 { println!("    \x1b[31m- {}\x1b[0m", b58(k)); }
            }

            /* Accounts only in source 2 */
            if !only2.is_empty() {
                if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                println!("  Accounts only in Source 2: {}", only2.len());
                for k in &only2 { println!("    \x1b[32m+ {}\x1b[0m", b58(k)); }
            }

            /* v5: Pre-load data (optimized batch loading) */
            let (cache1, cache2) = if v >= 5 {
                (Some(load_slot_data(&common, u1, p1)), Some(load_slot_data(&common, u2, p2)))
            } else {
                (None, None)
            };

            /* Compare common accounts */
            for key in &common {
                let (a1, a2) = (&u1[key], &u2[key]);
                let mut acc_diff = false;

                /* v4+: Account metadata */
                if v >= 4 {
                    let (l1, l2) = (a1.meta.lamports, a2.meta.lamports);
                    let (o1, o2) = (a1.meta.owner.key, a2.meta.owner.key);
                    let (e1, e2) = (a1.meta.executable, a2.meta.executable);
                    let (ds1, ds2) = (a1.data_size, a2.data_size);

                    if l1 != l2 || o1 != o2 || e1 != e2 || ds1 != ds2 {
                        if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                        if !acc_diff { println!("  Account {}:", b58(key)); acc_diff = true; }
                        if l1 != l2 { print_diff("Lamports", l1, l2); }
                        if o1 != o2 { print_diff("Owner", b58(&o1), b58(&o2)); }
                        if e1 != e2 { print_diff("Executable", e1, e2); }
                        if ds1 != ds2 { print_diff("Data Size", ds1, ds2); }
                    }
                }

                /* v5: Account data */
                if v >= 5 {
                    let data1 = cache1.as_ref().and_then(|c| c.get(key));
                    let data2 = cache2.as_ref().and_then(|c| c.get(key));
                    
                    let differs = match (data1, data2) {
                        (Some(d1), Some(d2)) => d1 != d2,
                        (None, None) => false,
                        _ => true,
                    };

                    if differs {
                        if !has_diff { println!("\nSlot {} - \x1b[31mMISMATCH\x1b[0m", slot); has_diff = true; }
                        if !acc_diff { println!("  Account {}:", b58(key)); acc_diff = true; }
                        println!("    Data:");
                        println!("      \x1b[31m- 1: {}\x1b[0m", data1.map(|d| hex(d)).unwrap_or("N/A".into()));
                        println!("      \x1b[32m+ 2: {}\x1b[0m", data2.map(|d| hex(d)).unwrap_or("N/A".into()));
                    }
                }

                if acc_diff { n_diff_accounts += 1; }
            }
        }
    }
    diff_accounts = n_diff_accounts;

    (has_diff, diff_accounts)
}
