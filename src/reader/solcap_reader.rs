use crate::model::structs::*;
use crate::reader::structures::{AccountUpdate, SolcapData};
use crate::reader::pcap_iter::{BlockHandler, IterationState, PcapIterator, PcapIterError, DEFAULT_BUFFER_SIZE};
use crate::utils::spinner::Spinner;
use pcap_parser::PcapBlockOwned;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem;
use std::path::Path;

/// Errors that can occur during solcap file reading
#[derive(Debug)]
pub enum SolcapReaderError {
    /// IO error when reading file
    IoError(std::io::Error),
    /// PCAP parsing error
    PcapError(String),
    /// Invalid solcap format
    InvalidFormat(String),
    /// Incomplete data
    IncompleteData(String),
}

impl From<std::io::Error> for SolcapReaderError {
    fn from(err: std::io::Error) -> Self {
        SolcapReaderError::IoError(err)
    }
}

impl From<PcapIterError> for SolcapReaderError {
    fn from(err: PcapIterError) -> Self {
        match err {
            PcapIterError::IoError(e) => SolcapReaderError::IoError(e),
            PcapIterError::PcapError(e) => SolcapReaderError::PcapError(e),
            PcapIterError::InvalidFormat(e) => SolcapReaderError::InvalidFormat(e),
            PcapIterError::IncompleteData(e) => SolcapReaderError::IncompleteData(e),
        }
    }
}

/// Block handler for parsing solcap files
struct SolcapParseHandler {
    data: SolcapData,
}

impl BlockHandler for SolcapParseHandler {
    type Error = SolcapReaderError;

    fn handle_block(
        &mut self,
        block: &PcapBlockOwned,
        state: &mut IterationState,
        _offset: usize,
    ) -> Result<(), Self::Error> {
        Self::process_block(block, &mut self.data, state)
    }

    fn handle_unexpected_eof(
        &mut self,
        state: &mut IterationState,
    ) -> Result<(), Self::Error> {
        // Allow partial files - just warn
        if state.blocks_processed > 0 {
            eprintln!("Warning: Unexpected EOF encountered (may be incomplete last block), but {} blocks were processed successfully", state.blocks_processed);
            Ok(())
        } else {
            Err(SolcapReaderError::IncompleteData(
                "File appears to be truncated or invalid".to_string()
            ))
        }
    }
}

impl SolcapParseHandler {
    fn process_block(
        block: &PcapBlockOwned,
        data: &mut SolcapData,
        state: &mut IterationState,
    ) -> Result<(), SolcapReaderError> {
        match block {
            PcapBlockOwned::NG(ng_block) => {
                use pcap_parser::pcapng::*;
                
                match ng_block {
                    Block::SectionHeader(_) => {
                        state.section_found = true;
                    }
                    Block::InterfaceDescription(_) => {
                        state.idb_found = true;
                    }
                    Block::EnhancedPacket(epb) => {
                        Self::process_enhanced_packet_block(epb, data, state.current_offset)?;
                    }
                    _ => {
                        // Ignore other block types for now
                    }
                }
            }
            _ => {
                // Legacy PCAP format not expected in solcap files
                return Err(SolcapReaderError::InvalidFormat(
                    "Legacy PCAP format not supported for solcap files".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Process an Enhanced Packet Block containing solcap data
    fn process_enhanced_packet_block(
        epb: &pcap_parser::pcapng::EnhancedPacketBlock,
        data: &mut SolcapData,
        current_offset: u64,
    ) -> Result<(), SolcapReaderError> {
        let packet_data = epb.data;
        
        if packet_data.len() < mem::size_of::<SolcapChunkIntHdr>() {
            return Err(SolcapReaderError::IncompleteData(
                "Packet too small for internal chunk header".to_string(),
            ));
        }

        // Parse the internal chunk header
        let int_hdr = unsafe {
            std::ptr::read_unaligned(packet_data.as_ptr() as *const SolcapChunkIntHdr)
        };

        let remaining_data = &packet_data[mem::size_of::<SolcapChunkIntHdr>()..];
        
        // Process based on block type
        match int_hdr.block_type {
            SOLCAP_WRITE_ACCOUNT_HDR => {
                Self::process_account_update(int_hdr.slot, int_hdr.txn_idx, remaining_data, data, current_offset)?;

            }
            SOLCAP_WRITE_BANK_PREIMAGE => {
                Self::process_bank_preimage(int_hdr.slot, remaining_data, data)?;
            }
            SOLCAP_WRITE_ACCOUNT_DATA => {
                // Account data blocks are handled as part of account header processing
                // We store the offset for later data retrieval
            }
            _ => {
                // Other message types (stake rewards, etc.) - ignore for now
            }
        }

        Ok(())
    }

    /// Process an account update message
    fn process_account_update(
        slot: u32,
        txn_idx: u64,
        data: &[u8],
        solcap_data: &mut SolcapData,
        current_offset: u64,
    ) -> Result<(), SolcapReaderError> {
        if data.len() < mem::size_of::<SolcapAccountUpdateHdr>() {
            return Err(SolcapReaderError::IncompleteData(
                "Insufficient data for account update header".to_string(),
            ));
        }

        // Parse account update header
        let update_hdr = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const SolcapAccountUpdateHdr)
        };

        // Calculate data offset (current position + header size)
        let data_offset = current_offset + mem::size_of::<SolcapChunkIntHdr>() as u64 + mem::size_of::<SolcapAccountUpdateHdr>() as u64;

        let account_update = AccountUpdate {
            key: update_hdr.key,
            meta: update_hdr.info,
            data_size: update_hdr.data_sz,
            data_offset,
            slot,
            txn_idx,
            file: None, // Solcap files don't use per-account file tracking
        };

        solcap_data.add_account_update(slot, account_update);
        Ok(())
    }

    /// Process a bank preimage message
    fn process_bank_preimage(
        slot: u32,
        data: &[u8],
        solcap_data: &mut SolcapData,
    ) -> Result<(), SolcapReaderError> {
        if data.len() < mem::size_of::<SolcapBankPreimage>() {
            return Err(SolcapReaderError::IncompleteData(
                "Insufficient data for bank preimage".to_string(),
            ));
        }

        // Parse bank preimage
        let bank_preimage = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const SolcapBankPreimage)
        };

        solcap_data.add_bank_preimage(slot, bank_preimage);
        Ok(())
    }
}

/// Reader for solcap files in pcapng format
pub struct SolcapReader<R: Read> {
    iterator: PcapIterator<R>,
}

impl SolcapReader<BufReader<File>> {
    /// Create a new SolcapReader from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SolcapReaderError> {
        let file = File::open(path)?;
        let buf_reader = BufReader::new(file);
        Self::new(buf_reader)
    }
}

impl<R: Read> SolcapReader<R> {
    /// Create a new SolcapReader from any Read implementation
    pub fn new(reader: R) -> Result<Self, SolcapReaderError> {
        let iterator = PcapIterator::with_buffer_size(reader, DEFAULT_BUFFER_SIZE)?;
        Ok(Self { iterator })
    }

    /// Parse the entire solcap file and build in-memory structures
    pub fn parse_file(&mut self) -> Result<SolcapData, SolcapReaderError> {
        let mut handler = SolcapParseHandler {
            data: SolcapData::new(),
        };

        self.iterator.iterate(&mut handler)?;
        self.iterator.validate_headers()?;

        Ok(handler.data)
    }
}

/// Read account data from a solcap file at a specific offset
/// 
/// This function allows you to retrieve the actual account data for a specific
/// account update by using the offset and size stored in the AccountUpdate structure.
/// 
/// # Arguments
/// * `path` - Path to the solcap file
/// * `offset` - Byte offset in the file where the account data starts
/// * `size` - Size of the account data in bytes
/// 
/// # Returns
/// The raw account data as a Vec<u8>
/// 
/// # Example
/// ```ignore
/// let account_update = /* get from SolcapData */;
/// let data = read_account_data_at_offset(
///     "capture.solcap",
///     account_update.data_offset,
///     account_update.data_size
/// )?;
/// ```
pub fn read_account_data_at_offset<P: AsRef<Path>>(
    path: P,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, SolcapReaderError> {
    // Open the file
    let mut file = File::open(path)?;
    
    // Seek to the offset
    file.seek(SeekFrom::Start(offset))?;
    
    // Allocate buffer and read the data
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)?;
    
    Ok(buffer)
}

/// Read account data for a specific AccountUpdate from a solcap file
/// 
/// This is a convenience wrapper around read_account_data_at_offset that takes
/// an AccountUpdate directly.
/// 
/// # Arguments
/// * `path` - Path to the solcap file
/// * `account_update` - The AccountUpdate containing offset and size information
/// 
/// # Returns
/// The raw account data as a Vec<u8>
pub fn read_account_data<P: AsRef<Path>>(
    path: P,
    account_update: &AccountUpdate,
) -> Result<Vec<u8>, SolcapReaderError> {
    read_account_data_at_offset(path, account_update.data_offset, account_update.data_size)
}

/// Convenience function to read a solcap file and return parsed data
pub fn read_solcap_file<P: AsRef<Path>>(path: P) -> Result<SolcapData, SolcapReaderError> {
    let spinner = Spinner::new("Ingesting solcap file...");
    let mut reader = SolcapReader::from_file(path)?;
    let result = reader.parse_file();
    spinner.finish_and_clear();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solcap_data_creation() {
        let data = SolcapData::new();
        assert_eq!(data.lowest_slot, u32::MAX);
        assert_eq!(data.highest_slot, 0);
        assert_eq!(data.slot_count(), 0);
        assert_eq!(data.total_account_updates(), 0);
    }

    #[test]
    fn test_slot_range_updates() {
        let mut data = SolcapData::new();
        
        // Add some slots
        data.update_slot_range(100);
        assert_eq!(data.lowest_slot, 100);
        assert_eq!(data.highest_slot, 100);
        assert_eq!(data.slot_count(), 1);
        
        data.update_slot_range(105);
        assert_eq!(data.lowest_slot, 100);
        assert_eq!(data.highest_slot, 105);
        assert_eq!(data.slot_count(), 6);
        
        data.update_slot_range(95);
        assert_eq!(data.lowest_slot, 95);
        assert_eq!(data.highest_slot, 105);
        assert_eq!(data.slot_count(), 11);
    }
}
