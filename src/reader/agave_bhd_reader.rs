use crate::model::structs::{Hash, Pubkey, SolanaAccountMeta};
use crate::reader::structures::SolcapData;
use crate::utils::spinner::Spinner;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Errors that can occur during Agave bank hash details reading
#[derive(Debug)]
pub enum AgaveBhdReaderError {
    /// IO error when reading files
    IoError(std::io::Error),
    /// JSON parsing error
    JsonError(serde_json::Error),
    /// Invalid format
    InvalidFormat(String),
    /// Directory not found or not a directory
    InvalidDirectory(String),
}

impl From<std::io::Error> for AgaveBhdReaderError {
    fn from(err: std::io::Error) -> Self {
        AgaveBhdReaderError::IoError(err)
    }
}

impl From<serde_json::Error> for AgaveBhdReaderError {
    fn from(err: serde_json::Error) -> Self {
        AgaveBhdReaderError::JsonError(err)
    }
}

/// Agave bank hash details JSON structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AgaveBankHashDetails {
    pub version: String,
    pub account_data_encoding: String,
    pub bank_hash_details: Vec<AgaveBankHashDetailEntry>,
}

/// Single bank hash detail entry
#[derive(Debug, Serialize, Deserialize)]
pub struct AgaveBankHashDetailEntry {
    pub slot: u32,
    pub bank_hash: String,
    pub parent_bank_hash: String,
    pub signature_count: u64,
    pub last_blockhash: String,
    pub accounts_lt_hash_checksum: String,
    pub accounts: Vec<AgaveAccountEntry>,
}

/// Single account entry in Agave format
#[derive(Debug, Serialize, Deserialize)]
pub struct AgaveAccountEntry {
    pub pubkey: String,
    pub hash: String,
    pub owner: String,
    pub lamports: u64,
    pub executable: bool,
    pub data: String, /* base64 encoded */
}

/// Reader for Agave bank hash details directories
pub struct AgaveBhdReader {
    directory_path: PathBuf,
}

impl AgaveBhdReader {
    /// Create a new AgaveBhdReader from a directory path
    pub fn from_directory<P: AsRef<Path>>(path: P) -> Result<Self, AgaveBhdReaderError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(AgaveBhdReaderError::InvalidDirectory(
                format!("Directory does not exist: {}", path.display()),
            ));
        }
        if !path.is_dir() {
            return Err(AgaveBhdReaderError::InvalidDirectory(
                format!("Path is not a directory: {}", path.display()),
            ));
        }
        Ok(Self {
            directory_path: path.to_path_buf(),
        })
    }

    /// Parse all JSON files in the directory and build in-memory structures
    /// Uses parallelization to process multiple files simultaneously
    pub fn parse_directory(&self) -> Result<SolcapData, AgaveBhdReaderError> {
        /* Collect all JSON file paths first */
        let entries = fs::read_dir(&self.directory_path)?;
        let mut json_files = Vec::new();
        
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            /* Only process .json files */
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                json_files.push(path);
            }
        }
        
        if json_files.is_empty() {
            return Ok(SolcapData::new());
        }
        
        /* Determine number of threads to use (cap at number of files or CPU count) */
        let num_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(json_files.len());
        
        /* Split files into chunks for each thread */
        let chunk_size = (json_files.len() + num_threads - 1) / num_threads;
        let file_chunks: Vec<Vec<_>> = json_files
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect();
        
        /* Process file chunks in parallel using scoped threads */
        let results = std::thread::scope(|s| {
            let handles: Vec<_> = file_chunks
                .into_iter()
                .map(|chunk| {
                    s.spawn(move || {
                        let mut local_data = SolcapData::new();
                        for path in chunk {
                            if let Err(e) = Self::process_json_file_static(&path, &mut local_data) {
                                eprintln!("Warning: Failed to process file {}: {:?}", path.display(), e);
                            }
                        }
                        local_data
                    })
                })
                .collect();
            
            /* Collect results from all threads */
            handles.into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        
        /* Merge all results */
        let mut final_data = SolcapData::new();
        for data in results {
            final_data.merge(data);
        }
        
        Ok(final_data)
    }

    /// Process a single JSON file (static version for parallel processing)
    fn process_json_file_static(
        path: &Path,
        data: &mut SolcapData,
    ) -> Result<(), AgaveBhdReaderError> {
        /* Read the file */
        let contents = fs::read_to_string(path)?;

        /* Parse JSON */
        let bhd: AgaveBankHashDetails = serde_json::from_str(&contents)?;

        /* Process each bank hash detail entry */
        for entry in bhd.bank_hash_details {
            Self::process_bank_hash_entry(&entry, data, path)?;
        }

        Ok(())
    }

    /// Process a single bank hash detail entry
    fn process_bank_hash_entry(
        entry: &AgaveBankHashDetailEntry,
        data: &mut SolcapData,
        source_file: &Path,
    ) -> Result<(), AgaveBhdReaderError> {
        let slot = entry.slot;

        /* Parse and add bank preimage */
        let bank_preimage = crate::model::structs::SolcapBankPreimage {
            bank_hash: Self::parse_hash(&entry.bank_hash)?,
            prev_bank_hash: Self::parse_hash(&entry.parent_bank_hash)?,
            accounts_lt_hash_checksum: Self::parse_hash(&entry.accounts_lt_hash_checksum)?,
            poh_hash: Self::parse_hash(&entry.last_blockhash)?,
            signature_cnt: entry.signature_count,
        };
        data.add_bank_preimage(slot, bank_preimage);

        /* Process accounts */
        for account in entry.accounts.iter() {
            let account_update = Self::parse_account_entry(
                account,
                slot,
                source_file,
            )?;
            data.add_account_update(slot, account_update);
        }

        Ok(())
    }

    /// Parse an account entry into an AccountUpdate
    fn parse_account_entry(
        account: &AgaveAccountEntry,
        slot: u32,
        source_file: &Path,
    ) -> Result<crate::reader::structures::AccountUpdate, AgaveBhdReaderError> {
        /* Parse pubkey */
        let key = Self::parse_pubkey(&account.pubkey)?;

        /* Parse owner */
        let owner = Self::parse_pubkey(&account.owner)?;

        /* Create account metadata */
        let meta = SolanaAccountMeta {
            lamports: account.lamports,
            owner,
            executable: if account.executable { 1 } else { 0 },
            padding: [0; 3],
        };

        /* Decode base64 data to get size */
        let data_size = if account.data.is_empty() {
            0
        } else {
            /* For base64, we can calculate the size
               or we can decode to get exact size */
            use base64::{Engine as _, engine::general_purpose};
            match general_purpose::STANDARD.decode(&account.data) {
                Ok(decoded) => decoded.len() as u64,
                Err(_) => {
                    /* If decode fails, assume empty data */
                    0
                }
            }
        };
        /* For Agave BHD, we don't have a specific offset in the file for data
           We store 0 as offset, but include the file path so data can be retrieved if needed */
        Ok(crate::reader::structures::AccountUpdate {
            key,
            meta,
            data_size,
            data_offset: 0, /* Not applicable for JSON format */
            slot,
            txn_idx: None, /* Agave BHD doesn't provide transaction indices */
            file: Some(source_file.to_string_lossy().to_string()),
        })
    }

    /// Parse a base58 encoded pubkey string
    fn parse_pubkey(s: &str) -> Result<Pubkey, AgaveBhdReaderError> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| {
                AgaveBhdReaderError::InvalidFormat(format!("Invalid base58 pubkey: {}", e))
            })?;

        if decoded.len() != 32 {
            return Err(AgaveBhdReaderError::InvalidFormat(
                format!("Pubkey must be 32 bytes, got {}", decoded.len()),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(Pubkey::new(key))
    }

    /// Parse a base58 encoded hash string
    fn parse_hash(s: &str) -> Result<Hash, AgaveBhdReaderError> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| {
                AgaveBhdReaderError::InvalidFormat(format!("Invalid base58 hash: {}", e))
            })?;

        if decoded.len() != 32 {
            return Err(AgaveBhdReaderError::InvalidFormat(
                format!("Hash must be 32 bytes, got {}", decoded.len()),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&decoded);
        Ok(Hash::new(hash))
    }
}

/// Read account data for a specific AccountUpdate from an Agave bank hash details file
/// 
/// Since Agave bank hash details store account data as base64 encoded strings in JSON,
/// this function reads the JSON file, finds the specific account, and decodes its data.
/// 
/// # Arguments
/// * `account_update` - The AccountUpdate containing the file path and account key
/// 
/// # Returns
/// The decoded account data as a Vec<u8>
/// 
/// # Note
/// This requires that the AccountUpdate has a file path set (which it should for Agave BHD)
pub fn read_account_data_from_bhd(
    account_update: &crate::reader::structures::AccountUpdate,
) -> Result<Vec<u8>, AgaveBhdReaderError> {
    /* Get the file path from the account update */
    let file_path = account_update.file.as_ref().ok_or_else(|| {
        AgaveBhdReaderError::InvalidFormat(
            "AccountUpdate does not have a file path set".to_string()
        )
    })?;
    
    /* Read and parse the JSON file */
    let contents = fs::read_to_string(file_path)?;
    let bhd: AgaveBankHashDetails = serde_json::from_str(&contents)?;
    
    /* Find the account in the file */
    let target_key = bs58::encode(&account_update.key.key).into_string();
    
    for entry in bhd.bank_hash_details {
        if entry.slot == account_update.slot {
            for account in &entry.accounts {
                if account.pubkey == target_key {
                    /* Decode the base64 data */
                    use base64::{Engine as _, engine::general_purpose};
                    return general_purpose::STANDARD
                        .decode(&account.data)
                        .map_err(|e| {
                            AgaveBhdReaderError::InvalidFormat(
                                format!("Failed to decode base64 data: {}", e)
                            )
                        });
                }
            }
        }
    }
    
    Err(AgaveBhdReaderError::InvalidFormat(
        format!("Account not found in file: {}", target_key)
    ))
}

/// Convenience function to read a bank hash details directory and return parsed data
pub fn read_agave_bhd_directory<P: AsRef<Path>>(
    path: P,
) -> Result<SolcapData, AgaveBhdReaderError> {
    let spinner = Spinner::new("Ingesting bank hash details directory...");
    let reader = AgaveBhdReader::from_directory(path)?;
    let result = reader.parse_directory();
    spinner.finish_and_clear();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pubkey() {
        /* Test with a valid base58 pubkey (all 1s) */
        let pubkey_str = "11111111111111111111111111111111";
        let result = AgaveBhdReader::parse_pubkey(pubkey_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_hash() {
        /* Test with a valid base58 hash */
        let hash_str = "HtVSNPupEb7voSXYhHG3xXasfjgYQGBuSYtKVWEN9HZ1";
        let result = AgaveBhdReader::parse_hash(hash_str);
        assert!(result.is_ok());
    }
}

