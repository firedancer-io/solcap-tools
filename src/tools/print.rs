use crate::reader::{read_solcap_file, SolcapReaderError};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/*
 Print information about a solcap file

 Verbosity levels:
 - 1: Only bank hash from preimage
 - 2: Full preimage data
 - 3: Level 2 + final account metadata
 - 4: Level 3 + account data

 # Arguments
 - `file_path` - Path to the solcap file
 - `verbosity` - Verbosity level (1-4)
 - `start_slot` - Optional starting slot to display (inclusive)
 - `end_slot` - Optional ending slot to display (inclusive)
 - `show_all_updates` - If true, shows all account updates; if false, shows only final updates
*/

pub fn print_solcap_info(
    file_path: &str,
    verbosity: u8,
    start_slot: Option<u32>,
    end_slot: Option<u32>,
    show_all_updates: bool,
) -> Result<(), SolcapReaderError> {
    match read_solcap_file(file_path) {
        Ok(data) => {
            println!("\n=== Solcap File Information ===");
            println!("Slot Range: {} - {}", data.lowest_slot, data.highest_slot);
            println!("Total Slots: {}", data.slot_count());
            println!("Total Account Updates (All): {}", data.total_account_updates());
            println!("Total Account Updates (Final): {}", data.total_account_updates_final());
            
            // Print bank preimages count
            let bank_preimage_count = data.bank_preimages.iter()
                .filter(|p| p.is_some())
                .count();
            println!("Bank Preimages: {}", bank_preimage_count);
            
            // Print detailed slot information based on verbosity
            if data.slot_count() > 0 {
                println!("\n=== Slot Details ===");
                
                // Get sorted list of slots
                let mut slots_with_data: Vec<u32> = data.bank_preimages.iter()
                    .enumerate()
                    .filter_map(|(idx, p)| {
                        if p.is_some() {
                            Some(data.lowest_slot + idx as u32)
                        } else {
                            None
                        }
                    })
                    .collect();
                
                // Also include slots with account updates
                for slot in data.slot_account_updates_all.keys() {
                    if !slots_with_data.contains(slot) {
                        slots_with_data.push(*slot);
                    }
                }
                slots_with_data.sort();
                
                // Filter slots based on start_slot and end_slot parameters
                let filtered_slots: Vec<u32> = slots_with_data.into_iter()
                    .filter(|slot| {
                        if let Some(start) = start_slot {
                            if *slot < start {
                                return false;
                            }
                        }
                        if let Some(end) = end_slot {
                            if *slot > end {
                                return false;
                            }
                        }
                        true
                    })
                    .collect();
                
                for slot in filtered_slots {
                    println!("\nSlot {}:", slot);
                    
                    // Print bank preimage based on verbosity
                    if let Some(preimage) = data.get_bank_preimage(slot) {
                        if verbosity >= 1 {
                            println!("  Bank Hash: {}", bs58::encode(preimage.bank_hash.hash).into_string());
                        }
                        
                        if verbosity >= 2 {
                            let signature_cnt = preimage.signature_cnt;
                            println!("  Bank Preimage:");
                            println!("    Prev Bank Hash: {}", bs58::encode(preimage.prev_bank_hash.hash).into_string());
                            println!("    Accounts LT Hash Checksum: {}", bs58::encode(preimage.accounts_lt_hash_checksum.hash).into_string());
                            println!("    POH Hash: {}", bs58::encode(preimage.poh_hash.hash).into_string());
                            println!("    Signature Count: {}", signature_cnt);
                            println!("  Account Updates (All): {}", data.slot_account_updates_all.get(&slot).unwrap().len());
                            println!("  Account Updates (Final): {}", data.slot_account_updates_final.get(&slot).unwrap().len());
                        }
                    }
                    
                    // Print account updates if verbosity >= 3
                    if verbosity >= 3 {
                        // Determine which updates to show based on flag
                        let (updates_label, updates_iter): (&str, Box<dyn Iterator<Item = &crate::reader::structures::AccountUpdate>>) = 
                            if show_all_updates {
                                ("All Account Updates", 
                                 Box::new(data.get_account_updates_all(slot)
                                     .map(|v| v.iter())
                                     .into_iter()
                                     .flatten()))
                            } else {
                                ("Final Account Updates",
                                 Box::new(data.get_account_updates_final_vec(slot)
                                     .map(|v| v.into_iter())
                                     .into_iter()
                                     .flatten()))
                            };
                        
                        // Collect updates to check if empty
                        let updates: Vec<_> = updates_iter.collect();
                        if !updates.is_empty() {
                            println!("  {}:", updates_label);
                            for update in updates {
                                let key = update.key.key;
                                let lamports = update.meta.lamports;
                                let owner = update.meta.owner.key;
                                let executable = update.meta.executable;
                                
                                println!("    Account: {}", bs58::encode(key).into_string());
                                println!("      Slot: {}", update.slot);
                                println!("      Lamports: {}", lamports);
                                println!("      Owner: {}", bs58::encode(owner).into_string());
                                println!("      Executable: {}", executable);
                                println!("      Data Size: {} bytes", update.data_size);
                                println!("      Transaction Index: {}", update.txn_idx);
                                
                                // Print account data if verbosity >= 4
                                if verbosity >= 4 && update.data_size > 0 {
                                    if let Ok(account_data) = read_account_data(file_path, update.data_offset, update.data_size) {
                                        println!("      Data: {}", hex::encode(&account_data));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            Ok(())
        }
        Err(e) => {
            eprintln!("Error reading solcap file: {:?}", e);
            Err(e)
        }
    }
}

/// Read account data from the solcap file at a specific offset
fn read_account_data(file_path: &str, offset: u64, size: u64) -> Result<Vec<u8>, SolcapReaderError> {
    let mut file = File::open(file_path)?;
    file.seek(SeekFrom::Start(offset))?;
    
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)?;
    
    Ok(buffer)
}
