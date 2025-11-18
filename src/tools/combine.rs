use crate::model::structs::*;
use crate::reader::pcap_iter::{PcapIterator, PcapIterError, DEFAULT_BUFFER_SIZE};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::mem;
use std::path::{Path, PathBuf};
use pcap_parser::PcapBlockOwned;

/// Errors that can occur during combining
#[derive(Debug)]
pub enum CombineError {
    /// IO error
    IoError(std::io::Error),
    /// PCAP parsing error
    PcapError(String),
    /// Invalid file structure
    InvalidStructure(String),
    /// No input files provided
    NoInputFiles,
}

impl From<std::io::Error> for CombineError {
    fn from(err: std::io::Error) -> Self {
        CombineError::IoError(err)
    }
}

impl From<PcapIterError> for CombineError {
    fn from(err: PcapIterError) -> Self {
        match err {
            PcapIterError::IoError(e) => CombineError::IoError(e),
            PcapIterError::PcapError(e) => CombineError::PcapError(e),
            PcapIterError::InvalidFormat(e) => CombineError::InvalidStructure(e),
            PcapIterError::IncompleteData(e) => CombineError::InvalidStructure(e),
        }
    }
}

impl std::fmt::Display for CombineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CombineError::IoError(e) => write!(f, "IO error: {}", e),
            CombineError::PcapError(e) => write!(f, "PCAP parsing error: {}", e),
            CombineError::InvalidStructure(msg) => write!(f, "Invalid file structure: {}", msg),
            CombineError::NoInputFiles => write!(f, "No input files provided"),
        }
    }
}

impl std::error::Error for CombineError {}

/// Statistics about the combine operation
#[derive(Debug, Default)]
pub struct CombineStats {
    pub input_files: usize,
    pub total_epb_blocks: u64,
    pub output_size: u64,
}

impl CombineStats {
    fn print_summary(&self, output_path: &Path) {
        println!("\n✓ Combining completed successfully!");
        println!("\nOutput File:  {}", output_path.display());
        println!("\nStatistics:");
        println!("  Input Files:      {}", self.input_files);
        println!("  Total EPB Blocks: {}", self.total_epb_blocks);
        println!("  Output Size:      {} bytes ({:.2} MB)", 
                 self.output_size,
                 self.output_size as f64 / (1024.0 * 1024.0));
    }
}

/// File with its modification time for sorting
struct FileWithTime {
    path: PathBuf,
    mtime: std::time::SystemTime,
}

/// Combine multiple solcap files into a single file
pub fn combine_solcap<P: AsRef<Path>>(
    input_paths: &[P],
    output_path: Option<P>,
    verbose: bool
) -> Result<CombineStats, CombineError> {
    if input_paths.is_empty() {
        return Err(CombineError::NoInputFiles);
    }
    
    // Collect files with their modification times
    let mut files_with_times = Vec::new();
    for path in input_paths {
        let path_ref = path.as_ref();
        let metadata = std::fs::metadata(path_ref)?;
        let mtime = metadata.modified()?;
        files_with_times.push(FileWithTime {
            path: path_ref.to_path_buf(),
            mtime,
        });
    }
    
    // Sort by modification time (oldest to newest)
    files_with_times.sort_by_key(|f| f.mtime);
    
    if verbose {
        println!("Files ordered by modification time (oldest to newest):");
        for (i, file) in files_with_times.iter().enumerate() {
            println!("  {}. {}", i + 1, file.path.display());
        }
        println!();
    }
    
    // Determine output path
    let output = if let Some(out) = output_path {
        out.as_ref().to_path_buf()
    } else {
        PathBuf::from("combined.solcap")
    };
    
    println!("Combining {} file(s) into: {}\n", files_with_times.len(), output.display());
    
    // Open output file
    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)?;
    let mut buf_writer = BufWriter::new(output_file);
    
    let mut stats = CombineStats {
        input_files: files_with_times.len(),
        ..Default::default()
    };
    
    let mut wrote_section_header = false;
    let mut wrote_idb = false;
    
    // Process each file in order
    for (index, file_info) in files_with_times.iter().enumerate() {
        if verbose {
            println!("[{}/{}] Processing: {}", 
                     index + 1, 
                     files_with_times.len(),
                     file_info.path.display());
        }
        
        let epb_count = process_file(
            &file_info.path,
            &mut buf_writer,
            &mut wrote_section_header,
            &mut wrote_idb,
            &mut stats,
            verbose
        )?;
        
        if verbose {
            println!("  ✓ Copied {} EPB blocks\n", epb_count);
        } else {
            println!("  ✓ {} - {} EPB blocks", file_info.path.display(), epb_count);
        }
    }
    
    // Flush output
    buf_writer.flush()?;
    drop(buf_writer);
    
    // Get final output size
    let output_metadata = std::fs::metadata(&output)?;
    stats.output_size = output_metadata.len();
    
    stats.print_summary(&output);
    
    Ok(stats)
}

/// Process a single input file
fn process_file<W: Write>(
    input_path: &Path,
    writer: &mut W,
    wrote_section_header: &mut bool,
    wrote_idb: &mut bool,
    stats: &mut CombineStats,
    verbose: bool,
) -> Result<u64, CombineError> {
    let input_file = File::open(input_path)?;
    let buf_reader = BufReader::new(input_file);
    
    // Create iterator - we'll use it for initialization but manually iterate for raw data access
    let mut iterator = PcapIterator::with_buffer_size(buf_reader, DEFAULT_BUFFER_SIZE)?;
    
    let mut epb_count = 0u64;
    let mut seen_section_header = false;
    let mut seen_idb = false;
    
    // Manual iteration to access raw data for writing
    use pcap_parser::traits::PcapReaderIterator;
    let reader = iterator.reader_mut();
    
    loop {
        let result = reader.next();
        
        match result {
            Ok((offset, block)) => {
                match &block {
                    PcapBlockOwned::NG(ng_block) => {
                        use pcap_parser::pcapng::*;
                        
                        match ng_block {
                            Block::SectionHeader(shb) => {
                                seen_section_header = true;
                                
                                // Only write the first Section Header we encounter
                                if !*wrote_section_header {
                                    // Validate magic number
                                    if shb.block_type != FD_SOLCAP_V2_FILE_MAGIC {
                                        return Err(CombineError::InvalidStructure(
                                            format!("Invalid magic number in {}: 0x{:08x}", 
                                                    input_path.display(), shb.block_type)
                                        ));
                                    }
                                    
                                    // Write the raw block data
                                    let data = reader.data();
                                    writer.write_all(&data[..offset])?;
                                    *wrote_section_header = true;
                                    
                                    if verbose {
                                        println!("  ✓ Section Header Block");
                                    }
                                } else if verbose {
                                    println!("  ⊘ Skipping duplicate Section Header");
                                }
                            }
                            Block::InterfaceDescription(_idb) => {
                                seen_idb = true;
                                
                                // Only write the first IDB we encounter
                                if !*wrote_idb {
                                    if !*wrote_section_header {
                                        return Err(CombineError::InvalidStructure(
                                            format!("IDB before Section Header in {}", input_path.display())
                                        ));
                                    }
                                    
                                    // Write the raw block data
                                    let data = reader.data();
                                    writer.write_all(&data[..offset])?;
                                    *wrote_idb = true;
                                    
                                    if verbose {
                                        println!("  ✓ Interface Description Block");
                                    }
                                } else if verbose {
                                    println!("  ⊘ Skipping duplicate IDB");
                                }
                            }
                            Block::EnhancedPacket(epb) => {
                                if !seen_section_header || !seen_idb {
                                    return Err(CombineError::InvalidStructure(
                                        format!("EPB before headers in {}", input_path.display())
                                    ));
                                }
                                
                                // Validate EPB has minimum data
                                let packet_data = epb.data;
                                if packet_data.len() < mem::size_of::<SolcapChunkIntHdr>() {
                                    if verbose {
                                        println!("  ⚠ Warning: Skipping invalid EPB (too small)");
                                    }
                                    reader.consume(offset);
                                    continue;
                                }
                                
                                // Write the raw EPB data
                                let data = reader.data();
                                writer.write_all(&data[..offset])?;
                                epb_count += 1;
                                stats.total_epb_blocks += 1;
                                
                                if verbose && epb_count == 1 {
                                    println!("  ✓ First EPB block");
                                } else if verbose && epb_count % 5000 == 0 {
                                    println!("  ... {} EPB blocks processed", epb_count);
                                }
                            }
                            _ => {
                                // Skip other block types
                                if verbose {
                                    println!("  ⊘ Skipping other block type");
                                }
                            }
                        }
                    }
                    _ => {
                        return Err(CombineError::InvalidStructure(
                            format!("Legacy PCAP format not supported in {}", input_path.display())
                        ));
                    }
                }
                
                reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => {
                break;
            }
            Err(pcap_parser::PcapError::Incomplete(_)) => {
                if let Err(_) = reader.refill() {
                    // Can't refill, reached end
                    if verbose {
                        println!("  ⚠ Warning: Incomplete block at end of file, skipping");
                    }
                    break;
                }
                continue;
            }
            Err(pcap_parser::PcapError::BufferTooSmall) => {
                let current_size = reader.data().len();
                let new_size = current_size * 2;
                if !reader.grow(new_size) {
                    if verbose {
                        println!("  ⚠ Warning: Block too large, skipping rest of file");
                    }
                    break;
                }
                if let Err(_) = reader.refill() {
                    if verbose {
                        println!("  ⚠ Warning: Incomplete block, skipping rest of file");
                    }
                    break;
                }
                continue;
            }
            Err(pcap_parser::PcapError::UnexpectedEof) => {
                if verbose {
                    println!("  ⚠ Warning: Unexpected EOF, stopping at last valid block");
                }
                break;
            }
            Err(e) => {
                if verbose {
                    println!("  ⚠ Warning: Parse error ({:?}), stopping at last valid block", e);
                }
                break;
            }
        }
    }
    
    // Verify we got required headers from first file
    if !seen_section_header {
        return Err(CombineError::InvalidStructure(
            format!("No Section Header found in {}", input_path.display())
        ));
    }
    
    if !seen_idb {
        return Err(CombineError::InvalidStructure(
            format!("No Interface Description Block found in {}", input_path.display())
        ));
    }
    
    Ok(epb_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_input() {
        let result = combine_solcap::<PathBuf>(&[], None::<PathBuf>, false);
        assert!(matches!(result, Err(CombineError::NoInputFiles)));
    }
}

