use crate::model::structs::*;
use crate::reader::pcap_iter::{PcapIterator, PcapIterError, DEFAULT_BUFFER_SIZE};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::mem;
use std::path::{Path, PathBuf};
use pcap_parser::PcapBlockOwned;

/// Errors that can occur during cleanup
#[derive(Debug)]
pub enum CleanupError {
    /// IO error
    IoError(std::io::Error),
    /// PCAP parsing error
    PcapError(String),
    /// Invalid file structure
    InvalidStructure(String),
}

impl From<std::io::Error> for CleanupError {
    fn from(err: std::io::Error) -> Self {
        CleanupError::IoError(err)
    }
}

impl From<PcapIterError> for CleanupError {
    fn from(err: PcapIterError) -> Self {
        match err {
            PcapIterError::IoError(e) => CleanupError::IoError(e),
            PcapIterError::PcapError(e) => CleanupError::PcapError(e),
            PcapIterError::InvalidFormat(e) => CleanupError::InvalidStructure(e),
            PcapIterError::IncompleteData(e) => CleanupError::InvalidStructure(e),
        }
    }
}

impl std::fmt::Display for CleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CleanupError::IoError(e) => write!(f, "IO error: {}", e),
            CleanupError::PcapError(e) => write!(f, "PCAP parsing error: {}", e),
            CleanupError::InvalidStructure(msg) => write!(f, "Invalid file structure: {}", msg),
        }
    }
}

impl std::error::Error for CleanupError {}

/// Statistics about the cleanup operation
#[derive(Debug, Default)]
pub struct CleanupStats {
    pub original_size: u64,
    pub cleaned_size: u64,
    pub blocks_kept: u64,
    pub blocks_removed: u64,
    pub section_header_found: bool,
    pub idb_found: bool,
    pub failure_reason: Option<String>,
    pub failure_offset: Option<u64>,
}

impl CleanupStats {
    fn print_summary(&self, original_path: &Path, output_path: &Path) {
        println!("\n✓ Cleanup completed successfully!");
        println!("\nOriginal File:  {}", original_path.display());
        println!("Cleaned File:   {}", output_path.display());
        println!("\nStatistics:");
        println!("  Original Size:    {} bytes ({:.2} MB)", 
                 self.original_size,
                 self.original_size as f64 / (1024.0 * 1024.0));
        println!("  Cleaned Size:     {} bytes ({:.2} MB)", 
                 self.cleaned_size,
                 self.cleaned_size as f64 / (1024.0 * 1024.0));
        println!("  Blocks Kept:      {}", self.blocks_kept);
        println!("  Blocks Removed:   {}", self.blocks_removed);
        
        if self.blocks_removed > 0 || self.failure_reason.is_some() {
            let bytes_removed = self.original_size.saturating_sub(self.cleaned_size);
            println!("  Data Removed:     {} bytes ({:.2} MB)", 
                     bytes_removed,
                     bytes_removed as f64 / (1024.0 * 1024.0));
            
            if let Some(ref reason) = self.failure_reason {
                println!("\n⚠ File truncated due to: {}", reason);
                if let Some(offset) = self.failure_offset {
                    println!("  Failure at offset: 0x{:08x} ({} bytes)", offset, offset);
                }
            }
        }
        
        if !self.section_header_found {
            println!("\n⚠ Warning: Section Header Block not found or invalid");
        }
        if !self.idb_found {
            println!("\n⚠ Warning: Interface Description Block not found or invalid");
        }
    }
}

/// Validates a block and returns whether it's valid
fn validate_block(
    block: &PcapBlockOwned,
    section_found: &mut bool,
    idb_found: &mut bool,
    current_offset: u64,
    verbose: bool,
) -> Result<bool, (String, u64)> {
    match block {
        PcapBlockOwned::NG(ng_block) => {
            use pcap_parser::pcapng::*;
            
            match ng_block {
                Block::SectionHeader(shb) => {
                    // Check if we already have a section header
                    if *section_found {
                        return Err(("Multiple Section Header blocks found".to_string(), current_offset));
                    }
                    
                    // Validate magic number
                    if shb.block_type != FD_SOLCAP_V2_FILE_MAGIC {
                        return Err((format!("Invalid Section Header magic number: 0x{:08x} (expected 0x{:08x})", 
                            shb.block_type, FD_SOLCAP_V2_FILE_MAGIC), current_offset));
                    }
                    
                    *section_found = true;
                    
                    if verbose {
                        println!("✓ Section Header Block (offset: 0x{:08x})", current_offset);
                    }
                    Ok(true)
                }
                Block::InterfaceDescription(idb) => {
                    // Check ordering
                    if !*section_found {
                        return Err(("Interface Description Block found before Section Header".to_string(), current_offset));
                    }
                    
                    if *idb_found {
                        return Err(("Multiple Interface Description blocks found".to_string(), current_offset));
                    }
                    
                    // Validate link type
                    let linktype_value = idb.linktype.0;
                    let expected_linktype = SOLCAP_IDB_HDR_LINK_TYPE as i32;
                    if linktype_value != expected_linktype {
                        return Err((format!("Invalid IDB link type: {} (expected {})", 
                            linktype_value, expected_linktype), current_offset));
                    }
                    
                    *idb_found = true;
                    
                    if verbose {
                        println!("✓ Interface Description Block (offset: 0x{:08x})", current_offset);
                    }
                    Ok(true)
                }
                Block::EnhancedPacket(epb) => {
                    // Check ordering
                    if !*section_found || !*idb_found {
                        return Err(("Enhanced Packet Block found before required headers".to_string(), current_offset));
                    }
                    
                    // Validate EPB has minimum data for internal header
                    let packet_data = epb.data;
                    if packet_data.len() < mem::size_of::<SolcapChunkIntHdr>() {
                        return Err((format!("EPB too small for internal header: {} bytes (need at least {})", 
                            packet_data.len(), mem::size_of::<SolcapChunkIntHdr>()), current_offset));
                    }
                    
                    Ok(true)
                }
                _ => {
                    // Other block types are allowed
                    if verbose {
                        println!("✓ Other block type (offset: 0x{:08x})", current_offset);
                    }
                    Ok(true)
                }
            }
        }
        _ => {
            // Legacy PCAP format not supported
            Err(("Legacy PCAP format not supported".to_string(), current_offset))
        }
    }
}

/// Clean up a solcap file by removing incomplete/malformed blocks
pub fn cleanup_solcap<P: AsRef<Path>>(input_path: P, verbose: bool) -> Result<CleanupStats, CleanupError> {
    let input_path = input_path.as_ref();
    
    // Generate output path with _clean suffix
    let output_path = generate_output_path(input_path);
    
    println!("Cleaning up solcap file: {}", input_path.display());
    println!("Output file: {}\n", output_path.display());
    
    if verbose {
        println!("Starting cleanup process...\n");
    }
    
    // Open input file
    let input_file = File::open(input_path)?;
    let original_size = input_file.metadata()?.len();
    let buf_reader = BufReader::new(input_file);
    
    // Open output file
    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_path)?;
    let mut buf_writer = BufWriter::new(output_file);
    
    // Create iterator - we'll use it for initialization but manually iterate for raw data access
    let mut iterator = PcapIterator::with_buffer_size(buf_reader, DEFAULT_BUFFER_SIZE)?;
    
    let mut stats = CleanupStats {
        original_size,
        ..Default::default()
    };
    
    let mut section_found = false;
    let mut idb_found = false;
    let mut truncate_at: Option<u64> = None;
    let mut failure_reason: Option<String> = None;
    let mut failure_offset: Option<u64> = None;
    
    if verbose {
        println!("Reading and validating blocks...\n");
    }
    
    // Use manual iteration to access raw data for writing
    use pcap_parser::traits::PcapReaderIterator;
    let reader = iterator.reader_mut();
    
    loop {
        let position_before = reader.position() as u64;
        let result = reader.next();
        
        match result {
            Ok((offset, block)) => {
                // Store offset and block type for later use
                let block_offset = offset;
                let is_epb = matches!(block, PcapBlockOwned::NG(pcap_parser::pcapng::Block::EnhancedPacket(_)));
                
                // Validate the block
                let validation_result = validate_block(&block, &mut section_found, &mut idb_found, position_before, verbose);
                
                // Drop block reference to release borrow before accessing reader.data()
                drop(block);
                
                match validation_result {
                    Ok(_) => {
                        // Block is valid, write it
                        let raw_data = reader.data();
                        let data_slice = &raw_data[..block_offset];
                        buf_writer.write_all(data_slice)?;
                        
                        stats.blocks_kept += 1;
                        stats.cleaned_size += block_offset as u64;
                        
                        // Update stats for headers
                        if section_found {
                            stats.section_header_found = true;
                        }
                        if idb_found {
                            stats.idb_found = true;
                        }
                        
                        if verbose && stats.blocks_kept == 1 && is_epb {
                            println!("✓ First EPB (offset: 0x{:08x})", position_before);
                        } else if verbose && stats.blocks_kept > 0 && stats.blocks_kept % 1000 == 0 {
                            println!("  ... processed {} blocks", stats.blocks_kept);
                        }
                        
                        reader.consume(block_offset);
                    }
                    Err((reason, offset)) => {
                        // Block is invalid, truncate here
                        truncate_at = Some(offset);
                        failure_reason = Some(reason);
                        failure_offset = Some(offset);
                        if verbose {
                            println!("\n✗ Invalid block at offset 0x{:08x}, truncating file here", offset);
                        }
                        break;
                    }
                }
            }
            Err(pcap_parser::PcapError::Eof) => {
                // Normal end of file
                if verbose {
                    println!("\n✓ Reached end of file normally");
                }
                break;
            }
            Err(pcap_parser::PcapError::Incomplete(_n)) => {
                // Try to refill and continue
                if let Err(_) = reader.refill() {
                    // Can't refill, truncate here
                    truncate_at = Some(position_before);
                    failure_reason = Some("Incomplete block at end of file".to_string());
                    failure_offset = Some(position_before);
                    if verbose {
                        println!("\n✗ Incomplete block at offset 0x{:08x}, truncating here", position_before);
                    }
                    break;
                }
                continue;
            }
            Err(pcap_parser::PcapError::BufferTooSmall) => {
                let current_size = reader.data().len();
                let new_size = current_size * 2;
                if !reader.grow(new_size) {
                    // Can't grow, truncate here
                    truncate_at = Some(position_before);
                    failure_reason = Some("Block too large to process".to_string());
                    failure_offset = Some(position_before);
                    if verbose {
                        println!("\n✗ Block too large at offset 0x{:08x}, truncating here", position_before);
                    }
                    break;
                }
                if let Err(_) = reader.refill() {
                    // Can't refill after growth, truncate here
                    truncate_at = Some(position_before);
                    failure_reason = Some("Incomplete block after buffer growth".to_string());
                    failure_offset = Some(position_before);
                    if verbose {
                        println!("\n✗ Incomplete block at offset 0x{:08x}, truncating here", position_before);
                    }
                    break;
                }
                continue;
            }
            Err(pcap_parser::PcapError::UnexpectedEof) => {
                // Unexpected EOF - truncate here
                truncate_at = Some(position_before);
                failure_reason = Some("Unexpected EOF encountered".to_string());
                failure_offset = Some(position_before);
                if verbose {
                    println!("\n✗ Unexpected EOF at offset 0x{:08x}, truncating here", position_before);
                }
                break;
            }
            Err(e) => {
                // Other parsing error - truncate here
                truncate_at = Some(position_before);
                failure_reason = Some(format!("Parsing error: {:?}", e));
                failure_offset = Some(position_before);
                if verbose {
                    println!("\n✗ Parsing error at offset 0x{:08x}: {:?}, truncating here", position_before, e);
                }
                break;
            }
        }
    }
    
    // Flush and close writer
    buf_writer.flush()?;
    drop(buf_writer);
    
    // Update stats
    stats.section_header_found = section_found;
    stats.idb_found = idb_found;
    stats.failure_reason = failure_reason;
    stats.failure_offset = failure_offset;
    
    // Calculate blocks removed
    if truncate_at.is_some() {
        stats.blocks_removed = 1; // At least one block was invalid
    }
    
    // Get final file size
    let final_size = std::fs::metadata(&output_path)?.len();
    stats.cleaned_size = final_size;
    
    // Print summary
    stats.print_summary(input_path, &output_path);
    
    Ok(stats)
}

/// Generate output path with _clean suffix
fn generate_output_path(input_path: &Path) -> PathBuf {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let stem = input_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let extension = input_path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("solcap");
    
    parent.join(format!("{}_clean.{}", stem, extension))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_output_path() {
        let input = Path::new("/path/to/file.solcap");
        let output = generate_output_path(input);
        assert_eq!(output, Path::new("/path/to/file_clean.solcap"));
        
        let input = Path::new("file.solcap");
        let output = generate_output_path(input);
        assert_eq!(output, Path::new("file_clean.solcap"));
    }
}

