use crate::model::structs::{Pubkey, SolanaAccountMeta, SolcapBankPreimage};
use std::collections::HashMap;

/// Common account information shared between different readers
#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// The account's public key
    pub key: Pubkey,
    /// Account metadata (lamports, owner, etc.)
    pub meta: SolanaAccountMeta,
    /// Size of the account data
    pub data_size: u64,
    /// Offset in the file where the account data starts
    pub data_offset: u64,
    /// Optional file path (used for bank_hash_details, blank for solcap)
    pub file: Option<String>,
}

/// Represents an account update with metadata and file offset for data
#[derive(Debug, Clone)]
pub struct AccountUpdate {
    /// The account's public key
    pub key: Pubkey,
    /// Account metadata (lamports, owner, etc.)
    pub meta: SolanaAccountMeta,
    /// Size of the account data
    pub data_size: u64,
    /// Offset in the file where the account data starts
    pub data_offset: u64,
    /// Slot when this update occurred
    pub slot: u32,
    /// Transaction index within the slot
    pub txn_idx: u64,
    /// Optional file path (used for bank_hash_details, blank for solcap)
    pub file: Option<String>,
}

/// In-memory representation of a solcap file's contents
#[derive(Debug)]
pub struct SolcapData {
    /// The lowest slot number found in the file
    pub lowest_slot: u32,
    /// The highest slot number found in the file  
    pub highest_slot: u32,
    /// Array of bank preimages indexed by (slot - lowest_slot)
    /// Index 0 corresponds to lowest_slot, index (highest_slot - lowest_slot) to highest_slot
    pub bank_preimages: Vec<Option<SolcapBankPreimage>>,
    /// Map from slot number to list of ALL account updates that occurred in that slot
    pub slot_account_updates_all: HashMap<u32, Vec<AccountUpdate>>,
    /// Map from slot number to map of account key to final account update (highest txn_idx)
    pub slot_account_updates_final: HashMap<u32, HashMap<[u8; 32], AccountUpdate>>,
}

impl SolcapData {
    /// Create a new empty SolcapData structure
    pub fn new() -> Self {
        Self {
            lowest_slot: u32::MAX,
            highest_slot: 0,
            bank_preimages: Vec::new(),
            slot_account_updates_all: HashMap::new(),
            slot_account_updates_final: HashMap::new(),
        }
    }

    /// Update the slot range and resize bank_preimages array if needed
    pub fn update_slot_range(&mut self, slot: u32) {
        let mut range_changed = false;
        
        // IMPORTANT: Save the OLD lowest_slot BEFORE updating it!
        // We need this to know which slots the existing preimages belong to.
        let old_lowest_slot = self.lowest_slot;

        // Update lowest slot
        if slot < self.lowest_slot {
            self.lowest_slot = slot;
            range_changed = true;
        }

        // Update highest slot
        if slot > self.highest_slot {
            self.highest_slot = slot;
            range_changed = true;
        }

        // Resize bank_preimages array if range changed
        if range_changed {
            let new_size = (self.highest_slot - self.lowest_slot + 1) as usize;
            let mut new_preimages = vec![None; new_size];
            
            // Copy existing preimages to new array with adjusted indices
            // Use old_lowest_slot (not self.lowest_slot) to calculate original slot numbers
            for (old_idx, preimage) in self.bank_preimages.iter().enumerate() {
                if let Some(preimage) = preimage {
                    let slot_for_old_idx = old_lowest_slot + old_idx as u32;
                    let new_idx = (slot_for_old_idx - self.lowest_slot) as usize;
                    if new_idx < new_preimages.len() {
                        new_preimages[new_idx] = Some(*preimage);
                    }
                }
            }
            
            self.bank_preimages = new_preimages;
        }
    }

    /// Add a bank preimage for a specific slot
    pub fn add_bank_preimage(&mut self, slot: u32, preimage: SolcapBankPreimage) {
        self.update_slot_range(slot);
        
        let idx = (slot - self.lowest_slot) as usize;
        if idx < self.bank_preimages.len() {
            self.bank_preimages[idx] = Some(preimage);
        }
    }

    /// Add an account update for a specific slot
    pub fn add_account_update(&mut self, slot: u32, update: AccountUpdate) {
        self.update_slot_range(slot);
        
        // Add to all updates
        self.slot_account_updates_all
            .entry(slot)
            .or_insert_with(Vec::new)
            .push(update.clone());
        
        // Add to final updates (only keep the one with highest txn_idx for each account)
        let final_updates = self.slot_account_updates_final
            .entry(slot)
            .or_insert_with(HashMap::new);
        
        let account_key = update.key.key;
        
        // Only update if this is the first update for this account or has higher txn_idx
        if let Some(existing) = final_updates.get(&account_key) {
            if update.txn_idx > existing.txn_idx {
                final_updates.insert(account_key, update);
            }
        } else {
            final_updates.insert(account_key, update);
        }
    }

    /// Get bank preimage for a specific slot
    pub fn get_bank_preimage(&self, slot: u32) -> Option<&SolcapBankPreimage> {
        if slot < self.lowest_slot || slot > self.highest_slot {
            return None;
        }
        
        let idx = (slot - self.lowest_slot) as usize;
        self.bank_preimages.get(idx)?.as_ref()
    }

    /// Get all account updates for a specific slot
    pub fn get_account_updates_all(&self, slot: u32) -> Option<&Vec<AccountUpdate>> {
        self.slot_account_updates_all.get(&slot)
    }
    
    /// Get final account updates (highest txn_idx per account) for a specific slot
    pub fn get_account_updates_final(&self, slot: u32) -> Option<&HashMap<[u8; 32], AccountUpdate>> {
        self.slot_account_updates_final.get(&slot)
    }
    
    /// Get final account updates as a Vec for a specific slot
    pub fn get_account_updates_final_vec(&self, slot: u32) -> Option<Vec<&AccountUpdate>> {
        self.slot_account_updates_final.get(&slot).map(|map| map.values().collect())
    }

    /// Get the total number of slots covered
    pub fn slot_count(&self) -> u32 {
        if self.highest_slot >= self.lowest_slot {
            self.highest_slot - self.lowest_slot + 1
        } else {
            0
        }
    }

    /// Get total number of account updates (all) across all slots
    pub fn total_account_updates(&self) -> usize {
        self.slot_account_updates_all.values().map(|v| v.len()).sum()
    }
    
    /// Get total number of final account updates across all slots
    pub fn total_account_updates_final(&self) -> usize {
        self.slot_account_updates_final.values().map(|m| m.len()).sum()
    }
    
    /// Merge another SolcapData into this one
    /// This is useful for combining results from parallel processing
    pub fn merge(&mut self, other: SolcapData) {
        // Merge bank preimages
        for (idx, preimage) in other.bank_preimages.iter().enumerate() {
            if let Some(preimage) = preimage {
                let slot = other.lowest_slot + idx as u32;
                self.add_bank_preimage(slot, *preimage);
            }
        }
        
        // Merge all account updates
        for (slot, updates) in other.slot_account_updates_all {
            for update in updates {
                self.add_account_update(slot, update);
            }
        }
    }
}

impl Default for SolcapData {
    fn default() -> Self {
        Self::new()
    }
}
