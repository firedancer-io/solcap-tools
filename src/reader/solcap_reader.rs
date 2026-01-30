/*! Solcap file reader - wraps pcap_parser for solcap-specific operations. */

use crate::model::structs::*;
use crate::reader::structures::{AccountUpdate, SolcapData};
use crate::utils::spinner::Spinner;
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader};
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem;
use std::path::Path;

/* Default buffer size (64MB) - large enough for big account data */
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Solcap reader error
#[derive(Debug)]
pub enum SolcapError {
    Io(std::io::Error),
    Parse(String),
    InvalidFormat(String),
}

pub type SolcapReaderError = SolcapError;
pub type PcapIterError = SolcapError;

impl From<std::io::Error> for SolcapError {
    fn from(err: std::io::Error) -> Self {
        SolcapError::Io(err)
    }
}

impl<I: std::fmt::Debug> From<PcapError<I>> for SolcapError {
    fn from(err: PcapError<I>) -> Self {
        SolcapError::Parse(format!("{:?}", err))
    }
}

impl std::fmt::Display for SolcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolcapError::Io(e) => write!(f, "IO error: {}", e),
            SolcapError::Parse(e) => write!(f, "Parse error: {}", e),
            SolcapError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for SolcapError {}

/// A parsed solcap chunk from an Enhanced Packet Block
#[derive(Debug, Clone)]
pub enum SolcapChunk {
    AccountUpdate {
        slot: u32,
        txn_idx: u64,
        key: Pubkey,
        meta: SolanaAccountMeta,
        data_size: u64,
        data_offset: u64,
    },
    BankPreimage {
        slot: u32,
        preimage: SolcapBankPreimage,
    },
    StakeAccountPayout {
        slot: u32,
        txn_idx: u64,
        payout: SolcapStakeAccountPayout,
    },
    StakeRewardEvent {
        slot: u32,
        txn_idx: u64,
        event: SolcapStakeRewardEvent,
    },
    StakeRewardsBegin {
        slot: u32,
        txn_idx: u64,
        begin: SolcapStakeRewardsBegin,
    },
}

/// Reader for solcap files - wraps pcap_parser for solcap-specific operations
pub struct SolcapReader<R: Read> {
    reader: PcapNGReader<R>,
    pub section_found: bool,
    pub idb_found: bool,
    current_offset: u64,
}

impl SolcapReader<BufReader<File>> {
    /// Open a solcap file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SolcapError> {
        let file = File::open(path)?;
        Self::new(BufReader::new(file))
    }
    
    /// Alias for compatibility
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SolcapError> {
        Self::open(path)
    }
}

impl<R: Read> SolcapReader<R> {
    /// Create reader from any Read source
    pub fn new(reader: R) -> Result<Self, SolcapError> {
        Self::with_buffer_size(reader, DEFAULT_BUFFER_SIZE)
    }

    pub fn with_buffer_size(reader: R, buffer_size: usize) -> Result<Self, SolcapError> {
        let pcap_reader = PcapNGReader::new(buffer_size, reader)?;
        Ok(Self {
            reader: pcap_reader,
            section_found: false,
            idb_found: false,
            current_offset: 0,
        })
    }

    /// Current position in file
    pub fn position(&self) -> u64 {
        self.current_offset
    }

    /// Access underlying reader for tools that need raw block access
    pub fn inner(&self) -> &PcapNGReader<R> {
        &self.reader
    }

    pub fn inner_mut(&mut self) -> &mut PcapNGReader<R> {
        &mut self.reader
    }

    /// Get next solcap chunk (skips non-EPB blocks, returns parsed chunk)
    pub fn next_chunk(&mut self) -> Result<Option<(SolcapChunk, u64)>, SolcapError> {
        loop {
            let offset = self.current_offset;
            
            /* Handle the next block */
            let result = self.reader.next();
            match result {
                Ok((size, block)) => {
                    /* Track header blocks and try to parse */
                    let chunk = match &block {
                        PcapBlockOwned::NG(ng_block) => {
                            use pcap_parser::pcapng::Block;
                            match ng_block {
                                Block::SectionHeader(_) => {
                                    self.section_found = true;
                                    None
                                }
                                Block::InterfaceDescription(_) => {
                                    self.idb_found = true;
                                    None
                                }
                                Block::EnhancedPacket(epb) => {
                                    Some(Self::parse_epb_static(epb.data, offset)?)
                                }
                                _ => None,
                            }
                        }
                        _ => return Err(SolcapError::InvalidFormat("Legacy PCAP not supported".into())),
                    };
                    
                    /* Consume and update offset */
                    self.reader.consume(size);
                    self.current_offset += size as u64;
                    
                    if let Some(c) = chunk {
                        return Ok(Some((c, offset)));
                    }
                    /* Not an EPB with solcap data, continue to next block */
                }
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_)) => {
                    self.reader.refill()?;
                    continue;
                }
                Err(PcapError::BufferTooSmall) => {
                    let new_size = self.reader.data().len() * 2;
                    if !self.reader.grow(new_size) {
                        return Err(SolcapError::InvalidFormat("Block too large".into()));
                    }
                    self.reader.refill()?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    
    /* Static version that doesn't need &self */
    fn parse_epb_static(data: &[u8], file_offset: u64) -> Result<SolcapChunk, SolcapError> {
        if data.len() < mem::size_of::<SolcapChunkIntHdr>() {
            return Err(SolcapError::InvalidFormat("Packet too small".into()));
        }

        let hdr = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const SolcapChunkIntHdr)
        };
        let payload = &data[mem::size_of::<SolcapChunkIntHdr>()..];
        let block_type = hdr.block_type;

        match block_type {
            SOLCAP_WRITE_ACCOUNT => {
                if payload.len() < mem::size_of::<SolcapAccountUpdateHdr>() {
                    return Err(SolcapError::InvalidFormat("Account header too small".into()));
                }
                let acct = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr() as *const SolcapAccountUpdateHdr)
                };
                let data_offset = file_offset 
                    + mem::size_of::<SolcapChunkEpbHdr>() as u64  /* EPB header */
                    + mem::size_of::<SolcapChunkIntHdr>() as u64
                    + mem::size_of::<SolcapAccountUpdateHdr>() as u64;
                
                Ok(SolcapChunk::AccountUpdate {
                    slot: hdr.slot,
                    txn_idx: hdr.txn_idx,
                    key: acct.key,
                    meta: acct.info,
                    data_size: acct.data_sz,
                    data_offset,
                })
            }
            SOLCAP_WRITE_BANK_PREIMAGE => {
                if payload.len() < mem::size_of::<SolcapBankPreimage>() {
                    return Err(SolcapError::InvalidFormat("Bank preimage too small".into()));
                }
                let preimage = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr() as *const SolcapBankPreimage)
                };
                Ok(SolcapChunk::BankPreimage { slot: hdr.slot, preimage })
            }
            SOLCAP_STAKE_ACCOUNT_PAYOUT => {
                if payload.len() < mem::size_of::<SolcapStakeAccountPayout>() {
                    return Err(SolcapError::InvalidFormat("Stake account payout too small".into()));
                }
                let payout = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr() as *const SolcapStakeAccountPayout)
                };
                Ok(SolcapChunk::StakeAccountPayout { slot: hdr.slot, txn_idx: hdr.txn_idx, payout })
            }
            SOLCAP_STAKE_REWARD_EVENT => {
                if payload.len() < mem::size_of::<SolcapStakeRewardEvent>() {
                    return Err(SolcapError::InvalidFormat("Stake reward event too small".into()));
                }
                let event = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr() as *const SolcapStakeRewardEvent)
                };
                Ok(SolcapChunk::StakeRewardEvent { slot: hdr.slot, txn_idx: hdr.txn_idx, event })
            }
            SOLCAP_STAKE_REWARDS_BEGIN => {
                if payload.len() < mem::size_of::<SolcapStakeRewardsBegin>() {
                    return Err(SolcapError::InvalidFormat("Stake rewards begin too small".into()));
                }
                let begin = unsafe {
                    std::ptr::read_unaligned(payload.as_ptr() as *const SolcapStakeRewardsBegin)
                };
                Ok(SolcapChunk::StakeRewardsBegin { slot: hdr.slot, txn_idx: hdr.txn_idx, begin })
            }
            _ => Err(SolcapError::InvalidFormat(format!("Unknown block type: {}", block_type))),
        }
    }

    /// Parse entire file into SolcapData structure
    pub fn parse(&mut self) -> Result<SolcapData, SolcapError> {
        let mut data = SolcapData::new();
        
        while let Some((chunk, _offset)) = self.next_chunk()? {
            match chunk {
                SolcapChunk::AccountUpdate { slot, txn_idx, key, meta, data_size, data_offset } => {
                    data.add_account_update(slot, AccountUpdate {
                        key, meta, data_size, data_offset, slot, txn_idx: Some(txn_idx), file: None,
                    });
                }
                SolcapChunk::BankPreimage { slot, preimage } => {
                    data.add_bank_preimage(slot, preimage);
                }
                /* Stake-related chunks - currently not stored in SolcapData */
                SolcapChunk::StakeAccountPayout { .. } => {}
                SolcapChunk::StakeRewardEvent { .. } => {}
                SolcapChunk::StakeRewardsBegin { .. } => {}
            }
        }
        
        if !self.section_found {
            return Err(SolcapError::InvalidFormat("No Section Header found".into()));
        }
        if !self.idb_found {
            return Err(SolcapError::InvalidFormat("No Interface Description Block found".into()));
        }
        
        Ok(data)
    }
    
    /// Alias for compatibility
    pub fn parse_file(&mut self) -> Result<SolcapData, SolcapError> {
        self.parse()
    }
}

/* ============================================================================
   Convenience functions
   ============================================================================ */

/* Read and parse a solcap file (with spinner) */
pub fn read_solcap_file<P: AsRef<Path>>(path: P) -> Result<SolcapData, SolcapError> {
    let spinner = Spinner::new("Ingesting solcap file...");
    let mut reader = SolcapReader::open(path)?;
    let result = reader.parse();
    spinner.finish_and_clear();
    result
}

/// Read account data at a specific file offset
pub fn read_account_data_at_offset<P: AsRef<Path>>(
    path: P,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, SolcapError> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Read account data for an AccountUpdate
pub fn read_account_data<P: AsRef<Path>>(
    path: P,
    account_update: &AccountUpdate,
) -> Result<Vec<u8>, SolcapError> {
    read_account_data_at_offset(path, account_update.data_offset, account_update.data_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solcap_data_new() {
        let data = SolcapData::new();
        assert_eq!(data.lowest_slot, u32::MAX);
        assert_eq!(data.highest_slot, 0);
        assert_eq!(data.slot_count(), 0);
    }

    #[test]
    fn test_slot_range() {
        let mut data = SolcapData::new();
        data.update_slot_range(100);
        assert_eq!(data.lowest_slot, 100);
        assert_eq!(data.highest_slot, 100);
        
        data.update_slot_range(50);
        assert_eq!(data.lowest_slot, 50);
        assert_eq!(data.highest_slot, 100);
    }
}
