use crate::reader::{AgaveBhdReaderError, SolcapData, SolcapReaderError};
use crate::utils::spinner::Spinner;
use std::collections::HashSet;
use std::path::Path;

/// Errors that can occur during diffing
#[derive(Debug)]
pub enum DiffError {
    /// Error reading solcap file
    SolcapError(SolcapReaderError),
    /// Error reading Agave bank hash details
    AgaveError(AgaveBhdReaderError),
    /// IO error
    IoError(std::io::Error),
    /// Path doesn't exist
    PathNotFound(String),
}

impl From<SolcapReaderError> for DiffError {
    fn from(err: SolcapReaderError) -> Self {
        DiffError::SolcapError(err)
    }
}

impl From<AgaveBhdReaderError> for DiffError {
    fn from(err: AgaveBhdReaderError) -> Self {
        DiffError::AgaveError(err)
    }
}

impl From<std::io::Error> for DiffError {
    fn from(err: std::io::Error) -> Self {
        DiffError::IoError(err)
    }
}

/// Parse a path (either a file or directory) into SolcapData with spinner
fn parse_path<P: AsRef<Path>>(path: P, source: &str) -> Result<SolcapData, DiffError> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(DiffError::PathNotFound(format!(
            "Path does not exist: {}",
            path.display()
        )));
    }

    // Start spinner with source and path (bold "Ingesting Source X:")
    let spinner = Spinner::new(&format!("\x1b[1mIngesting {}\x1b[0m \x1b[2m{}\x1b[0m", source, path.display()));

    let data = if path.is_dir() {
        // Parse as Agave bank hash details directory (without its own spinner)
        parse_agave_bhd_directory_no_spinner(path)?
    } else {
        // Parse as solcap file (without its own spinner)
        parse_solcap_file_no_spinner(path)?
    };

    // Finish spinner with stats on next line
    let stats = format!(
        "    Slots: {} - {} \x1b[2m({} slots, {} final account updates)\x1b[0m",
        data.lowest_slot,
        data.highest_slot,
        data.slot_count(),
        data.total_account_updates_final()
    );
    spinner.finish_with_lines(vec![&stats]);

    Ok(data)
}

/// Parse solcap file without spinner (used by parse_path which has its own spinner)
fn parse_solcap_file_no_spinner<P: AsRef<Path>>(path: P) -> Result<SolcapData, DiffError> {
    use crate::reader::solcap_reader::SolcapReader;
    let mut reader = SolcapReader::from_file(path)?;
    Ok(reader.parse_file()?)
}

/// Parse Agave BHD directory without spinner (used by parse_path which has its own spinner)
fn parse_agave_bhd_directory_no_spinner<P: AsRef<Path>>(
    path: P,
) -> Result<SolcapData, DiffError> {
    use crate::reader::agave_bhd_reader::AgaveBhdReader;
    let reader = AgaveBhdReader::from_directory(path)?;
    Ok(reader.parse_directory()?)
}

/// Format a pubkey as base58 string
fn format_pubkey(key: &[u8; 32]) -> String {
    bs58::encode(key).into_string()
}

/// Format a hash as base58 string
fn format_hash(hash: &[u8; 32]) -> String {
    bs58::encode(hash).into_string()
}

/// Diff two SolcapData structures
pub fn diff_solcap<P1: AsRef<Path>, P2: AsRef<Path>>(
    path1: P1,
    path2: P2,
    verbosity: u8,
    start_slot: Option<u32>,
    end_slot: Option<u32>,
) -> Result<(), DiffError> {
    // Parse both paths (spinner will show progress and stats)
    println!("\n         \x1b[1;33mSolcap Diff\x1b[0m");
    println!("─────────────────────────────\n");

    let data1 = parse_path(&path1, "Source 1")?;
    let data2 = parse_path(&path2, "Source 2")?;

    // Find common slots
    let slots1: HashSet<u32> = data1.slot_account_updates_final.keys().copied().collect();
    let slots2: HashSet<u32> = data2.slot_account_updates_final.keys().copied().collect();

    let common_slots: Vec<u32> = slots1
        .intersection(&slots2)
        .copied()
        .filter(|&slot| {
            let after_start = start_slot.map_or(true, |s| slot >= s);
            let before_end = end_slot.map_or(true, |e| slot <= e);
            after_start && before_end
        })
        .collect();

    let mut common_slots = common_slots;
    common_slots.sort_unstable();

    if common_slots.is_empty() {
        println!("\nNo common slots found to compare.");
        return Ok(());
    }

    println!("\nComparing {} common slots", common_slots.len());

    println!("\n{}", "=".repeat(80));

    // Diff each common slot
    let mut total_differing_slots = 0;
    let mut total_differing_accounts = 0;

    for slot in common_slots {
        let (has_diff, diff_accounts) = diff_slot(slot, &data1, &data2, verbosity)?;
        if has_diff {
            total_differing_slots += 1;
        }
        total_differing_accounts += diff_accounts;
    }

    println!("\n{}", "=".repeat(80));
    println!("Summary:");
    println!("  Total differing slots: {}", total_differing_slots);
    println!("  Total differing accounts: {}", total_differing_accounts);

    Ok(())
}

/// Diff a single slot between two SolcapData structures
/// Returns (has_differences, count_of_differing_accounts)
fn diff_slot(slot: u32, data1: &SolcapData, data2: &SolcapData, verbosity: u8) -> Result<(bool, usize), DiffError> {
    let updates1 = data1.get_account_updates_final(slot);
    let updates2 = data2.get_account_updates_final(slot);

    if updates1.is_none() || updates2.is_none() {
        return Ok((false, 0));
    }

    let updates1 = updates1.unwrap();
    let updates2 = updates2.unwrap();

    // Compare bank preimages if verbosity >= 1
    let mut has_diff = false;
    let mut differing_accounts = 0;

    if verbosity >= 1 {
        let preimage1 = data1.get_bank_preimage(slot);
        let preimage2 = data2.get_bank_preimage(slot);

        match (preimage1, preimage2) {
            (Some(p1), Some(p2)) => {
                // Compare bank hashes
                if p1.bank_hash.hash != p2.bank_hash.hash {
                    if !has_diff {
                        println!("\nSlot {} - MISMATCH", slot);
                        has_diff = true;
                    }
                    println!("  Bank Hash:");
                    println!("    \x1b[31m- 1: {}\x1b[0m", format_hash(&p1.bank_hash.hash));
                    println!("    \x1b[32m+ 2: {}\x1b[0m", format_hash(&p2.bank_hash.hash));
                }

                if verbosity >= 2 {
                    // Compare full preimage
                    if p1.prev_bank_hash.hash != p2.prev_bank_hash.hash {
                        if !has_diff {
                            println!("\nSlot {} - MISMATCH", slot);
                            has_diff = true;
                        }
                        println!("  Previous Bank Hash:");
                        println!("    \x1b[31m- 1: {}\x1b[0m", format_hash(&p1.prev_bank_hash.hash));
                        println!("    \x1b[32m+ 2: {}\x1b[0m", format_hash(&p2.prev_bank_hash.hash));
                    }

                    if p1.accounts_lt_hash_checksum.hash != p2.accounts_lt_hash_checksum.hash {
                        if !has_diff {
                            println!("\nSlot {} - MISMATCH", slot);
                            has_diff = true;
                        }
                        println!("  Accounts LT Hash Checksum:");
                        println!("    \x1b[31m- 1: {}\x1b[0m", format_hash(&p1.accounts_lt_hash_checksum.hash));
                        println!("    \x1b[32m+ 2: {}\x1b[0m", format_hash(&p2.accounts_lt_hash_checksum.hash));
                    }

                    if p1.poh_hash.hash != p2.poh_hash.hash {
                        if !has_diff {
                            println!("\nSlot {} - MISMATCH", slot);
                            has_diff = true;
                        }
                        println!("  PoH Hash:");
                        println!("    \x1b[31m- 1: {}\x1b[0m", format_hash(&p1.poh_hash.hash));
                        println!("    \x1b[32m+ 2: {}\x1b[0m", format_hash(&p2.poh_hash.hash));
                    }

                    // Copy packed fields to local variables
                    let sig_cnt1 = p1.signature_cnt;
                    let sig_cnt2 = p2.signature_cnt;
                    if sig_cnt1 != sig_cnt2 {
                        if !has_diff {
                            println!("\nSlot {} - MISMATCH", slot);
                            has_diff = true;
                        }
                        println!("  Signature Count:");
                        println!("    \x1b[31m- 1: {}\x1b[0m", sig_cnt1);
                        println!("    \x1b[32m+ 2: {}\x1b[0m", sig_cnt2);
                    }
                }
            }
            (None, Some(_)) => {
                println!("\nSlot {} - WARNING: Bank preimage missing in source 1", slot);
            }
            (Some(_), None) => {
                println!("\nSlot {} - WARNING: Bank preimage missing in source 2", slot);
            }
            (None, None) => {
                // Both missing, skip
            }
        }
    }

    // Compare accounts if verbosity >= 3
    if verbosity >= 3 {
        // Find accounts in both, only in 1, only in 2
        let keys1: HashSet<[u8; 32]> = updates1.keys().copied().collect();
        let keys2: HashSet<[u8; 32]> = updates2.keys().copied().collect();

        let common_keys: HashSet<[u8; 32]> = keys1.intersection(&keys2).copied().collect();
        let only_in_1: HashSet<[u8; 32]> = keys1.difference(&keys2).copied().collect();
        let only_in_2: HashSet<[u8; 32]> = keys2.difference(&keys1).copied().collect();

        if !only_in_1.is_empty() {
            if !has_diff {
                println!("\nSlot {} - MISMATCH", slot);
                has_diff = true;
            }
            println!("  Source 1 ONLY Accounts: {}", only_in_1.len());
            if verbosity >= 4 {
                for key in only_in_1.iter().take(10) {
                    println!("  \x1b[31m- {}\x1b[0m", format_pubkey(key));
                }
                if only_in_1.len() > 10 {
                    println!("  ... and {} more", only_in_1.len() - 10);
                }
            }
            println!();
        }

        if !only_in_2.is_empty() {
            if !has_diff {
                println!("\nSlot {} - MISMATCH", slot);
                has_diff = true;
            }
            println!("  Source 2 ONLY Accounts: {}", only_in_2.len());
            if verbosity >= 4 {
                for key in only_in_2.iter().take(10) {
                    println!("  \x1b[32m+ {}\x1b[0m", format_pubkey(key));
                }
                if only_in_2.len() > 10 {
                    println!("  ... and {} more", only_in_2.len() - 10);
                }
            }
            println!();
        }

        // Compare common accounts
        for key in &common_keys {
            let acc1 = &updates1[key];
            let acc2 = &updates2[key];

            if !accounts_equal(acc1, acc2, verbosity) {
                differing_accounts += 1;

                if !has_diff {
                    println!("\nSlot {} - MISMATCH", slot);
                    has_diff = true;
                }

                if verbosity >= 4 {
                    println!("  Account {}:", format_pubkey(key));
                    print_account_diff(acc1, acc2);
                }
            }
        }

        if differing_accounts > 0 && verbosity < 4 {
            if !has_diff {
                println!("\nSlot {} - MISMATCH", slot);
                has_diff = true;
            }
            println!("  {} accounts have different values", differing_accounts);
        }
    }

    Ok((has_diff, differing_accounts))
}

/// Check if two accounts are equal based on metadata
fn accounts_equal(
    acc1: &crate::reader::structures::AccountUpdate,
    acc2: &crate::reader::structures::AccountUpdate,
    _verbosity: u8,
) -> bool {
    // Compare metadata
    acc1.meta.lamports == acc2.meta.lamports
        && acc1.meta.owner.key == acc2.meta.owner.key
        && acc1.meta.executable == acc2.meta.executable
        && acc1.data_size == acc2.data_size
}

/// Print differences between two accounts
fn print_account_diff(
    acc1: &crate::reader::structures::AccountUpdate,
    acc2: &crate::reader::structures::AccountUpdate,
) {
    // Copy packed fields to local variables to avoid unaligned references
    let lamports1 = acc1.meta.lamports;
    let lamports2 = acc2.meta.lamports;
    let owner1 = acc1.meta.owner.key;
    let owner2 = acc2.meta.owner.key;
    let executable1 = acc1.meta.executable;
    let executable2 = acc2.meta.executable;
    let data_size1 = acc1.data_size;
    let data_size2 = acc2.data_size;

    if lamports1 != lamports2 {
        println!("    Lamports:");
        println!("      \x1b[31m- 1: {}\x1b[0m", lamports1);
        println!("      \x1b[32m+ 2: {}\x1b[0m", lamports2);
    }
    if owner1 != owner2 {
        println!("    Owner:");
        println!("      \x1b[31m- 1: {}\x1b[0m", format_pubkey(&owner1));
        println!("      \x1b[32m+ 2: {}\x1b[0m", format_pubkey(&owner2));
    }
    if executable1 != executable2 {
        println!("    Executable:");
        println!("      \x1b[31m- 1: {}\x1b[0m", executable1);
        println!("      \x1b[32m+ 2: {}\x1b[0m", executable2);
    }
    if data_size1 != data_size2 {
        println!("    Data Size:");
        println!("      \x1b[31m- 1: {}\x1b[0m", data_size1);
        println!("      \x1b[32m+ 2: {}\x1b[0m", data_size2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_pubkey() {
        let key = [0u8; 32];
        let formatted = format_pubkey(&key);
        // System program pubkey (all zeros)
        assert_eq!(formatted, "11111111111111111111111111111111");
    }
}

