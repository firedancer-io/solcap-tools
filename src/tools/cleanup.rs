use crate::model::structs::*;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::mem;
use std::path::{Path, PathBuf};
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader};
use pcap_parser::traits::PcapReaderIterator;

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

impl<I: std::fmt::Debug> From<PcapError<I>> for CleanupError {
    fn from(err: PcapError<I>) -> Self {
        CleanupError::PcapError(format!("{:?}", err))
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
        
        if self.blocks_removed > 0 {
            let bytes_removed = self.original_size.saturating_sub(self.cleaned_size);
            println!("  Data Removed:     {} bytes ({:.2} MB)", 
                     bytes_removed,
                     bytes_removed as f64 / (1024.0 * 1024.0));
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
    
    // Create PCAP reader
    let mut pcap_reader = PcapNGReader::new(64 * 1024 * 1024, buf_reader)?;
    
    let mut stats = CleanupStats {
        original_size,
        ..Default::default()
    };
    
    let mut section_found = false;
    let mut idb_found = false;
    let mut block_count = 0;
    
    if verbose {
        println!("Reading and copying valid blocks...\n");
    }
    
    loop {
        let position_before = pcap_reader.position() as u64;
        let result = pcap_reader.next();
        
        match result {
            Ok((offset, block)) => {
                // Validate the block before writing
                match &block {
                    PcapBlockOwned::NG(ng_block) => {
                        use pcap_parser::pcapng::*;
                        
                        match ng_block {
                            Block::SectionHeader(shb) => {
                                if section_found {
                                    eprintln!("Warning: Multiple section headers found, stopping at first section");
                                    break;
                                }
                                
                                // Validate magic number
                                if shb.block_type != FD_SOLCAP_V2_FILE_MAGIC {
                                    return Err(CleanupError::InvalidStructure(
                                        format!("Invalid magic number: 0x{:08x}", shb.block_type)
                                    ));
                                }
                                
                                section_found = true;
                                stats.section_header_found = true;
                                
                                if verbose {
                                    println!("✓ Section Header Block (offset: 0x{:08x})", position_before);
                                }
                            }
                            Block::InterfaceDescription(_idb) => {
                                if !section_found {
                                    return Err(CleanupError::InvalidStructure(
                                        "IDB found before Section Header".to_string()
                                    ));
                                }
                                if idb_found {
                                    eprintln!("Warning: Multiple IDB blocks found, keeping first one");
                                    break;
                                }
                                
                                idb_found = true;
                                stats.idb_found = true;
                                
                                if verbose {
                                    println!("✓ Interface Description Block (offset: 0x{:08x})", position_before);
                                }
                            }
                            Block::EnhancedPacket(epb) => {
                                if !section_found || !idb_found {
                                    return Err(CleanupError::InvalidStructure(
                                        "EPB found before Section Header or IDB".to_string()
                                    ));
                                }
                                
                                // Validate EPB has minimum data for internal header
                                let packet_data = epb.data;
                                if packet_data.len() < mem::size_of::<SolcapChunkIntHdr>() {
                                    if verbose {
                                        println!("✗ Invalid EPB at offset 0x{:08x} (too small for internal header), stopping here", position_before);
                                    }
                                    stats.blocks_removed += 1;
                                    break;
                                }
                                
                                block_count += 1;
                                
                                if verbose && block_count == 1 {
                                    println!("✓ First EPB (offset: 0x{:08x})", position_before);
                                } else if verbose && block_count % 1000 == 0 {
                                    println!("  ... processed {} EPB blocks", block_count);
                                }
                            }
                            _ => {
                                // Other block types are allowed
                                if verbose {
                                    println!("✓ Other block type (offset: 0x{:08x})", position_before);
                                }
                            }
                        }
                    }
                    _ => {
                        return Err(CleanupError::InvalidStructure(
                            "Legacy PCAP format not supported".to_string()
                        ));
                    }
                }
                
                // Write the raw block data to output
                // We need to get the raw data from the reader
                let data_to_write = pcap_reader.data();
                let data_slice = &data_to_write[..offset];
                buf_writer.write_all(data_slice)?;
                
                stats.blocks_kept += 1;
                stats.cleaned_size += offset as u64;
                
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => {
                // Normal end of file
                if verbose {
                    println!("\n✓ Reached end of file normally");
                }
                break;
            }
            Err(PcapError::Incomplete(_n)) => {
                // Try to refill and continue
                if let Err(_) = pcap_reader.refill() {
                    // Can't refill, we've hit the end
                    if verbose {
                        println!("\n✓ Reached incomplete block at offset 0x{:08x}, stopping here", position_before);
                    }
                    stats.blocks_removed += 1;
                    break;
                }
                continue;
            }
            Err(PcapError::BufferTooSmall) => {
                let current_size = pcap_reader.data().len();
                let new_size = current_size * 2;
                if !pcap_reader.grow(new_size) {
                    if verbose {
                        println!("\n✗ Block too large at offset 0x{:08x}, stopping here", position_before);
                    }
                    stats.blocks_removed += 1;
                    break;
                }
                if let Err(_) = pcap_reader.refill() {
                    if verbose {
                        println!("\n✓ Reached incomplete block at offset 0x{:08x}, stopping here", position_before);
                    }
                    stats.blocks_removed += 1;
                    break;
                }
                continue;
            }
            Err(PcapError::UnexpectedEof) => {
                // Incomplete block at end of file
                if verbose {
                    println!("\n✓ Encountered unexpected EOF at offset 0x{:08x}, stopping before incomplete block", position_before);
                }
                stats.blocks_removed += 1;
                break;
            }
            Err(e) => {
                // Other parsing error
                if verbose {
                    println!("\n✗ Parsing error at offset 0x{:08x}: {:?}, stopping here", position_before, e);
                }
                stats.blocks_removed += 1;
                break;
            }
        }
    }
    
    // Flush output buffer
    buf_writer.flush()?;
    drop(buf_writer);
    
    // Verify we got minimum required blocks
    if !stats.section_header_found {
        return Err(CleanupError::InvalidStructure(
            "No valid Section Header Block found".to_string()
        ));
    }
    
    if !stats.idb_found {
        return Err(CleanupError::InvalidStructure(
            "No valid Interface Description Block found".to_string()
        ));
    }
    
    if verbose {
        println!("\nFlushing output file...");
    }
    
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

