use crate::model::structs::*;
use crate::reader::pcap_iter::{BlockHandler, IterationState, PcapIterator, PcapIterError, DEFAULT_BUFFER_SIZE};
use std::fs::{File, read_dir};
use std::io::BufReader;
use std::mem;
use std::path::{Path, PathBuf};
use pcap_parser::PcapBlockOwned;

/// Errors that can occur during solcap file verification
#[derive(Debug)]
pub enum VerifyError {
    /// IO error when reading file
    IoError(std::io::Error),
    /// PCAP parsing error
    PcapError(String),
    /// Missing Section Header Block
    MissingSectionHeader,
    /// Invalid Section Header Block
    InvalidSectionHeader(String),
    /// Missing Interface Description Block
    MissingInterfaceDescription,
    /// Invalid Interface Description Block
    InvalidInterfaceDescription(String),
    /// IDB appears after EPB blocks
    IdbAfterEpb,
    /// Invalid block type (expected EPB)
    InvalidBlockType(u32, u64), // block_type, offset
    /// Invalid EPB structure
    InvalidEpb(String),
    /// Invalid internal chunk header
    InvalidInternalHeader(String, u64), // error message, offset
    /// Malformed block
    MalformedBlock(String, u64), // error message, offset
}

impl From<std::io::Error> for VerifyError {
    fn from(err: std::io::Error) -> Self {
        VerifyError::IoError(err)
    }
}

impl From<PcapIterError> for VerifyError {
    fn from(err: PcapIterError) -> Self {
        match err {
            PcapIterError::IoError(e) => VerifyError::IoError(e),
            PcapIterError::PcapError(e) => VerifyError::PcapError(e),
            PcapIterError::InvalidFormat(e) => VerifyError::MalformedBlock(e, 0),
            PcapIterError::IncompleteData(e) => VerifyError::MalformedBlock(e, 0),
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::IoError(e) => write!(f, "IO error: {}", e),
            VerifyError::PcapError(e) => write!(f, "PCAP parsing error: {}", e),
            VerifyError::MissingSectionHeader => write!(f, "Missing Section Header Block"),
            VerifyError::InvalidSectionHeader(msg) => write!(f, "Invalid Section Header: {}", msg),
            VerifyError::MissingInterfaceDescription => write!(f, "Missing Interface Description Block"),
            VerifyError::InvalidInterfaceDescription(msg) => write!(f, "Invalid Interface Description Block: {}", msg),
            VerifyError::IdbAfterEpb => write!(f, "Interface Description Block found after Enhanced Packet Blocks"),
            VerifyError::InvalidBlockType(block_type, offset) => write!(f, "Invalid block type {} at offset 0x{:x} (expected EPB type {})", block_type, offset, SOLCAP_PCAPNG_BLOCK_TYPE_EPB),
            VerifyError::InvalidEpb(msg) => write!(f, "Invalid Enhanced Packet Block: {}", msg),
            VerifyError::InvalidInternalHeader(msg, offset) => write!(f, "Invalid internal chunk header at offset 0x{:x}: {}", offset, msg),
            VerifyError::MalformedBlock(msg, offset) => write!(f, "Malformed block at offset 0x{:x}: {}", offset, msg),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Statistics collected during verification
#[derive(Debug, Default)]
pub struct VerifyStats {
    pub section_header_found: bool,
    pub idb_found: bool,
    pub epb_count: u64,
    pub account_update_count: u64,
    pub bank_preimage_count: u64,
    pub stake_reward_count: u64,
    pub other_message_count: u64,
    pub total_bytes: u64,
}

impl VerifyStats {
    fn new() -> Self {
        Self::default()
    }

    fn print_summary(&self) {
        println!("\n✓ Verification completed successfully!");
        println!("\nFile Statistics:");
        println!("  Section Header:       {}", if self.section_header_found { "✓" } else { "✗" });
        println!("  Interface Desc Block: {}", if self.idb_found { "✓" } else { "✗" });
        println!("  EPB Blocks:           {}", self.epb_count);
        println!("\nMessage Types:");
        println!("  Account Updates:      {}", self.account_update_count);
        println!("  Bank Preimages:       {}", self.bank_preimage_count);
        println!("  Stake Rewards:        {}", self.stake_reward_count);
        println!("  Other Messages:       {}", self.other_message_count);
        println!("\nTotal File Size:        {} bytes ({:.2} MB)", 
                 self.total_bytes, 
                 self.total_bytes as f64 / (1024.0 * 1024.0));
    }
}

/// Verify a solcap file or directory of solcap files
pub fn verify_solcap<P: AsRef<Path>>(path: P, verbose: bool) -> Result<VerifyStats, VerifyError> {
    let path_ref = path.as_ref();
    
    if path_ref.is_dir() {
        verify_directory(path_ref, verbose)
    } else {
        verify_file(path_ref, verbose)
    }
}

/// Verify all .solcap files in a directory
fn verify_directory(dir_path: &Path, verbose: bool) -> Result<VerifyStats, VerifyError> {
    println!("Scanning directory: {}\n", dir_path.display());
    
    // Find all .solcap files in the directory
    let entries = read_dir(dir_path)?;
    let mut solcap_files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file() && 
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "solcap")
                .unwrap_or(false)
        })
        .collect();
    
    if solcap_files.is_empty() {
        println!("No .solcap files found in directory");
        return Ok(VerifyStats::default());
    }
    
    // Sort files by name for consistent output
    solcap_files.sort();
    
    println!("Found {} .solcap file(s) to verify\n", solcap_files.len());
    println!("{}", "=".repeat(80));
    
    // Verify each file and collect results
    let mut total_stats = VerifyStats::new();
    let mut successful_files = 0;
    let mut failed_files = Vec::new();
    
    for (index, file_path) in solcap_files.iter().enumerate() {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        println!("\n[{}/{}] Verifying: {}", index + 1, solcap_files.len(), file_name);
        println!("{}", "-".repeat(80));
        
        match verify_file(file_path, verbose) {
            Ok(stats) => {
                successful_files += 1;
                total_stats.epb_count += stats.epb_count;
                total_stats.account_update_count += stats.account_update_count;
                total_stats.bank_preimage_count += stats.bank_preimage_count;
                total_stats.stake_reward_count += stats.stake_reward_count;
                total_stats.other_message_count += stats.other_message_count;
                total_stats.total_bytes += stats.total_bytes;
                
                if !verbose {
                    println!("✓ Valid ({} EPB blocks, {:.2} MB)", 
                             stats.epb_count,
                             stats.total_bytes as f64 / (1024.0 * 1024.0));
                }
            }
            Err(e) => {
                failed_files.push((file_name.to_string(), e));
                println!("✗ Failed: {}", match failed_files.last() {
                    Some((_, err)) => format!("{}", err),
                    None => "Unknown error".to_string(),
                });
            }
        }
    }
    
    // Print summary
    println!("\n{}", "=".repeat(80));
    println!("\n📊 BATCH VERIFICATION SUMMARY\n");
    println!("Total Files:          {}", solcap_files.len());
    println!("Successful:           {} ✓", successful_files);
    println!("Failed:               {} ✗", failed_files.len());
    
    if !failed_files.is_empty() {
        println!("\nFailed Files:");
        for (name, error) in &failed_files {
            println!("  ✗ {}: {}", name, error);
        }
    }
    
    if successful_files > 0 {
        println!("\nAggregate Statistics (successful files only):");
        println!("  Total EPB Blocks:     {}", total_stats.epb_count);
        println!("  Account Updates:      {}", total_stats.account_update_count);
        println!("  Bank Preimages:       {}", total_stats.bank_preimage_count);
        println!("  Stake Rewards:        {}", total_stats.stake_reward_count);
        println!("  Total Data Size:      {} bytes ({:.2} MB)", 
                 total_stats.total_bytes,
                 total_stats.total_bytes as f64 / (1024.0 * 1024.0));
    }
    
    println!("\n{}", "=".repeat(80));
    
    // Return error if any files failed
    if !failed_files.is_empty() {
        return Err(VerifyError::MalformedBlock(
            format!("{} file(s) failed verification", failed_files.len()),
            0
        ));
    }
    
    Ok(total_stats)
}

/// Block handler for verification
struct VerifyHandler {
    stats: VerifyStats,
    verbose: bool,
    epb_seen: bool,
}

impl BlockHandler for VerifyHandler {
    type Error = VerifyError;

    fn handle_block(
        &mut self,
        block: &PcapBlockOwned,
        state: &mut IterationState,
        offset: usize,
    ) -> Result<(), Self::Error> {
        self.stats.total_bytes += offset as u64;
        verify_block(block, &mut self.stats, state, &mut self.epb_seen, self.verbose)
    }

    fn handle_unexpected_eof(
        &mut self,
        _state: &mut IterationState,
    ) -> Result<(), Self::Error> {
        // Unexpected EOF means the file is incomplete/corrupted
        let msg = if self.stats.epb_count > 0 {
            format!("Unexpected EOF after {} blocks - file is incomplete/truncated", self.stats.epb_count)
        } else {
            "File appears to be truncated or invalid".to_string()
        };
        Err(VerifyError::MalformedBlock(msg, 0))
    }
}

/// Verify a single solcap file structure
fn verify_file<P: AsRef<Path>>(path: P, verbose: bool) -> Result<VerifyStats, VerifyError> {
    let file = File::open(path.as_ref())?;
    let file_size = file.metadata()?.len();
    let buf_reader = BufReader::new(file);
    
    if verbose {
        println!("Verifying solcap file: {}", path.as_ref().display());
        println!("File size: {} bytes ({:.2} MB)\n", file_size, file_size as f64 / (1024.0 * 1024.0));
    }

    let mut iterator = PcapIterator::with_buffer_size(buf_reader, DEFAULT_BUFFER_SIZE)?;
    let mut handler = VerifyHandler {
        stats: VerifyStats::new(),
        verbose,
        epb_seen: false,
    };
    
    if verbose {
        println!("Starting verification...\n");
    }

    iterator.iterate(&mut handler)?;

    // Final validation
    if !iterator.state().section_found {
        return Err(VerifyError::MissingSectionHeader);
    }

    if !iterator.state().idb_found {
        return Err(VerifyError::MissingInterfaceDescription);
    }

    if verbose {
        handler.stats.print_summary();
    }

    Ok(handler.stats)
}

/// Verify a single PCAP block
fn verify_block(
    block: &PcapBlockOwned,
    stats: &mut VerifyStats,
    state: &mut IterationState,
    epb_seen: &mut bool,
    verbose: bool,
) -> Result<(), VerifyError> {
    let current_offset = state.current_offset;
    match block {
        PcapBlockOwned::NG(ng_block) => {
            use pcap_parser::pcapng::*;
            
            match ng_block {
                Block::SectionHeader(shb) => {
                    if verbose {
                        println!("[0x{:08x}] Section Header Block", current_offset);
                    }
                    
                    // Verify block type (acts as magic number in pcapng)
                    if shb.block_type != FD_SOLCAP_V2_FILE_MAGIC {
                        return Err(VerifyError::InvalidSectionHeader(
                            format!("Invalid block type: expected 0x{:08x}, got 0x{:08x}", 
                                    FD_SOLCAP_V2_FILE_MAGIC, shb.block_type)
                        ));
                    }
                    
                    // Check byte order magic
                    let byte_order_magic = shb.bom;
                    if byte_order_magic != FD_SOLCAP_V2_BYTE_ORDER_MAGIC {
                        if verbose {
                            println!("  Warning: Unexpected byte order magic: 0x{:08x} (expected 0x{:08x})", 
                                     byte_order_magic, FD_SOLCAP_V2_BYTE_ORDER_MAGIC);
                        }
                    }
                    
                    if verbose {
                        println!("  ✓ Valid block type: 0x{:08x}", shb.block_type);
                        println!("  ✓ Version: {}.{}", shb.major_version, shb.minor_version);
                    }
                    
                    state.section_found = true;
                    stats.section_header_found = true;
                }
                Block::InterfaceDescription(idb) => {
                    if *epb_seen {
                        return Err(VerifyError::IdbAfterEpb);
                    }
                    
                    if verbose {
                        println!("[0x{:08x}] Interface Description Block", current_offset);
                    }
                    
                    // Verify link type - convert both to i32 for comparison
                    let linktype_value = idb.linktype.0;
                    let expected_linktype = SOLCAP_IDB_HDR_LINK_TYPE as i32;
                    if linktype_value != expected_linktype {
                        return Err(VerifyError::InvalidInterfaceDescription(
                            format!("Invalid link type: expected {}, got {}", 
                                    expected_linktype, linktype_value)
                        ));
                    }
                    
                    // Verify snap length (should be 0 for unlimited)
                    if idb.snaplen != SOLCAP_IDB_HDR_SNAP_LEN {
                        if verbose {
                            println!("  Warning: Unexpected snap length: {} (expected {})", 
                                     idb.snaplen, SOLCAP_IDB_HDR_SNAP_LEN);
                        }
                    }
                    
                    if verbose {
                        println!("  ✓ Valid link type: {}", linktype_value);
                        println!("  ✓ Snap length: {}", idb.snaplen);
                    }
                    
                    state.idb_found = true;
                    stats.idb_found = true;
                }
                Block::EnhancedPacket(epb) => {
                    *epb_seen = true;
                    
                    if verbose && stats.epb_count == 0 {
                        println!("[0x{:08x}] First Enhanced Packet Block", current_offset);
                    }
                    
                    // Verify EPB structure and internal header
                    verify_enhanced_packet_block(epb, stats, current_offset, verbose)?;
                    
                    stats.epb_count += 1;
                    
                    if verbose && stats.epb_count % 1000 == 0 {
                        println!("  ... processed {} EPB blocks", stats.epb_count);
                    }
                }
                _ => {
                    // Other block types are allowed but not used in solcap
                    if verbose {
                        println!("[0x{:08x}] Other block type (allowed but unused)", current_offset);
                    }
                }
            }
        }
        _ => {
            // Legacy PCAP format not supported
            return Err(VerifyError::InvalidBlockType(0, current_offset));
        }
    }
    Ok(())
}

/// Verify an Enhanced Packet Block and its internal chunk header
fn verify_enhanced_packet_block(
    epb: &pcap_parser::pcapng::EnhancedPacketBlock,
    stats: &mut VerifyStats,
    current_offset: u64,
    verbose: bool,
) -> Result<(), VerifyError> {
    let packet_data = epb.data;
    
    // Verify minimum size for internal chunk header
    if packet_data.len() < mem::size_of::<SolcapChunkIntHdr>() {
        return Err(VerifyError::InvalidEpb(
            format!("Packet too small for internal chunk header: {} bytes (need at least {})", 
                    packet_data.len(), mem::size_of::<SolcapChunkIntHdr>())
        ));
    }

    // Parse the internal chunk header
    let int_hdr = unsafe {
        std::ptr::read_unaligned(packet_data.as_ptr() as *const SolcapChunkIntHdr)
    };

    // Copy packed struct fields to avoid unaligned references
    let block_type = int_hdr.block_type;
    let slot = int_hdr.slot;
    let txn_idx = int_hdr.txn_idx;
    
    // Verify the block type signature
    match block_type {
        SOLCAP_WRITE_ACCOUNT_HDR => {
            stats.account_update_count += 1;
            
            // Verify there's enough data for the account update header
            let remaining_data = &packet_data[mem::size_of::<SolcapChunkIntHdr>()..];
            if remaining_data.len() < mem::size_of::<SolcapAccountUpdateHdr>() {
                return Err(VerifyError::InvalidInternalHeader(
                    format!("Insufficient data for account update header: {} bytes (need {})", 
                            remaining_data.len(), mem::size_of::<SolcapAccountUpdateHdr>()),
                    current_offset
                ));
            }
            
            if verbose && stats.account_update_count == 1 {
                println!("  ✓ Account Update (slot {}, txn_idx {})", slot, txn_idx);
            }
        }
        SOLCAP_WRITE_BANK_PREIMAGE => {
            stats.bank_preimage_count += 1;
            
            // Verify there's enough data for the bank preimage
            let remaining_data = &packet_data[mem::size_of::<SolcapChunkIntHdr>()..];
            if remaining_data.len() < mem::size_of::<SolcapBankPreimage>() {
                return Err(VerifyError::InvalidInternalHeader(
                    format!("Insufficient data for bank preimage: {} bytes (need {})", 
                            remaining_data.len(), mem::size_of::<SolcapBankPreimage>()),
                    current_offset
                ));
            }
            
            if verbose && stats.bank_preimage_count == 1 {
                println!("  ✓ Bank Preimage (slot {})", slot);
            }
        }
        SOLCAP_STAKE_ACCOUNT_PAYOUT | SOLCAP_STAKE_REWARDS_BEGIN | 
        SOLCAP_WRITE_STAKE_REWARD_EVENT | SOLCAP_WRITE_VOTE_ACCOUNT_PAYOUT => {
            stats.stake_reward_count += 1;
            
            if verbose && stats.stake_reward_count == 1 {
                println!("  ✓ Stake/Reward message type {} (slot {})", block_type, slot);
            }
        }
        _ => {
            // Unknown block type - this might be a newer version or corrupted data
            return Err(VerifyError::InvalidInternalHeader(
                format!("Unknown block type: {} (valid types: {}, {}, {}, {}, {}, {}, {})", 
                        block_type,
                        SOLCAP_WRITE_ACCOUNT_HDR,
                        SOLCAP_WRITE_ACCOUNT_DATA,
                        SOLCAP_STAKE_ACCOUNT_PAYOUT,
                        SOLCAP_STAKE_REWARDS_BEGIN,
                        SOLCAP_WRITE_BANK_PREIMAGE,
                        SOLCAP_WRITE_STAKE_REWARD_EVENT,
                        SOLCAP_WRITE_VOTE_ACCOUNT_PAYOUT),
                current_offset
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_stats_creation() {
        let stats = VerifyStats::new();
        assert_eq!(stats.epb_count, 0);
        assert_eq!(stats.account_update_count, 0);
        assert_eq!(stats.bank_preimage_count, 0);
    }
}

