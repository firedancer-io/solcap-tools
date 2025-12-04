use crate::model::structs::*;
use crate::reader::{SolcapReader, SolcapError, DEFAULT_BUFFER_SIZE};
use crate::utils::{HeaderState, BlockValidation, validate_block, validate_epb_payload};
use std::fs::{File, OpenOptions, read_dir};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use pcap_parser::traits::PcapReaderIterator;

/// Errors that can occur during solcap file verification
#[derive(Debug)]
pub enum VerifyError {
    IoError(std::io::Error),
    PcapError(String),
    MissingSectionHeader,
    MissingInterfaceDescription,
    InvalidBlock(String, u64),
    MalformedBlock(String, u64),
}

impl From<std::io::Error> for VerifyError {
    fn from(err: std::io::Error) -> Self {
        VerifyError::IoError(err)
    }
}

impl From<SolcapError> for VerifyError {
    fn from(err: SolcapError) -> Self {
        match err {
            SolcapError::Io(e) => VerifyError::IoError(e),
            SolcapError::Parse(e) => VerifyError::PcapError(e),
            SolcapError::InvalidFormat(e) => VerifyError::MalformedBlock(e, 0),
        }
    }
}

impl From<(String, u64)> for VerifyError {
    fn from((msg, offset): (String, u64)) -> Self {
        VerifyError::InvalidBlock(msg, offset)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::IoError(e) => write!(f, "IO error: {}", e),
            VerifyError::PcapError(e) => write!(f, "PCAP parsing error: {}", e),
            VerifyError::MissingSectionHeader => write!(f, "Missing Section Header Block"),
            VerifyError::MissingInterfaceDescription => write!(f, "Missing Interface Description Block"),
            VerifyError::InvalidBlock(msg, offset) => {
                write!(f, "Invalid block at offset 0x{:x}: {}", offset, msg)
            }
            VerifyError::MalformedBlock(msg, offset) => {
                write!(f, "Malformed block at offset 0x{:x}: {}", offset, msg)
            }
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
    pub stake_account_payout_count: u64,
    pub stake_reward_event_count: u64,
    pub stake_rewards_begin_count: u64,
    pub total_bytes: u64,
    /* Cleanup-specific stats */
    pub blocks_kept: u64,
    pub failure_reason: Option<String>,
    pub failure_offset: Option<u64>,
    pub output_path: Option<PathBuf>,
}

impl VerifyStats {
    fn print_summary(&self, verbose: bool) {
        if self.output_path.is_some() {
            println!("\n✓ Verification and cleanup completed successfully!");
        } else {
            println!("\n✓ Verification completed successfully!");
        }
        
        println!("\nFile Statistics:");
        println!("  Section Header:       {}", if self.section_header_found { "✓" } else { "✗" });
        println!("  Interface Desc Block: {}", if self.idb_found { "✓" } else { "✗" });
        println!("  EPB Blocks:           {}", self.epb_count);
        
        if verbose {
            println!("\nMessage Types:");
            println!("  Account Updates:        {}", self.account_update_count);
            println!("  Bank Preimages:         {}", self.bank_preimage_count);
            println!("  Stake Account Payouts:  {}", self.stake_account_payout_count);
            println!("  Stake Reward Events:    {}", self.stake_reward_event_count);
            println!("  Stake Rewards Begins:   {}", self.stake_rewards_begin_count);
        }
        
        println!("\nTotal File Size:        {} bytes ({:.2} MB)", 
                 self.total_bytes, 
                 self.total_bytes as f64 / (1024.0 * 1024.0));
        
        if let Some(ref output) = self.output_path {
            println!("\nCleaned Output:         {}", output.display());
            println!("  Blocks Written:       {}", self.blocks_kept);
            
            if let Some(ref reason) = self.failure_reason {
                println!("\n⚠ File truncated due to: {}", reason);
                if let Some(offset) = self.failure_offset {
                    println!("  Failure at offset: 0x{:08x} ({} bytes)", offset, offset);
                }
            }
        }
    }
}

/* Generate output path with _clean suffix */
fn generate_clean_output_path(input_path: &Path) -> PathBuf {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let stem = input_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let extension = input_path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("solcap");
    
    parent.join(format!("{}_clean.{}", stem, extension))
}

/* Verify a solcap file or directory of solcap files
   If output_path is Some, write cleaned output (valid blocks only) */
pub fn verify_solcap<P: AsRef<Path>>(
    path: P, 
    verbose: bool,
    output_path: Option<P>,
) -> Result<VerifyStats, VerifyError> {
    let path_ref = path.as_ref();
    
    if path_ref.is_dir() {
        if output_path.is_some() {
            return Err(VerifyError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot use output flag with directory input"
            )));
        }
        verify_directory(path_ref, verbose)
    } else {
        verify_file(path_ref, verbose, output_path.map(|p| p.as_ref().to_path_buf()))
    }
}

/* Verify all .solcap files in a directory */
fn verify_directory(dir_path: &Path, verbose: bool) -> Result<VerifyStats, VerifyError> {
    println!("Scanning directory: {}\n", dir_path.display());
    
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
    
    solcap_files.sort();
    
    println!("Found {} .solcap file(s) to verify\n", solcap_files.len());
    println!("{}", "=".repeat(80));
    
    let mut total_stats = VerifyStats::default();
    let mut successful_files = 0;
    let mut failed_files = Vec::new();
    
    for (index, file_path) in solcap_files.iter().enumerate() {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        println!("\n[{}/{}] Verifying: {}", index + 1, solcap_files.len(), file_name);
        println!("{}", "-".repeat(80));
        
        match verify_file(file_path, verbose, None) {
            Ok(stats) => {
                successful_files += 1;
                total_stats.epb_count += stats.epb_count;
                total_stats.account_update_count += stats.account_update_count;
                total_stats.bank_preimage_count += stats.bank_preimage_count;
                total_stats.stake_account_payout_count += stats.stake_account_payout_count;
                total_stats.stake_reward_event_count += stats.stake_reward_event_count;
                total_stats.stake_rewards_begin_count += stats.stake_rewards_begin_count;
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
        println!("  Total EPB Blocks:       {}", total_stats.epb_count);
        println!("  Account Updates:        {}", total_stats.account_update_count);
        println!("  Bank Preimages:         {}", total_stats.bank_preimage_count);
        println!("  Stake Account Payouts:  {}", total_stats.stake_account_payout_count);
        println!("  Stake Reward Events:    {}", total_stats.stake_reward_event_count);
        println!("  Stake Rewards Begins:   {}", total_stats.stake_rewards_begin_count);
        println!("  Total Data Size:        {} bytes ({:.2} MB)", 
                 total_stats.total_bytes,
                 total_stats.total_bytes as f64 / (1024.0 * 1024.0));
    }
    
    println!("\n{}", "=".repeat(80));
    
    if !failed_files.is_empty() {
        return Err(VerifyError::MalformedBlock(
            format!("{} file(s) failed verification", failed_files.len()),
            0
        ));
    }
    
    Ok(total_stats)
}

/* Verify a single solcap file structure
   If output_path is Some, write cleaned output (valid blocks only) */
fn verify_file(
    path: &Path, 
    verbose: bool,
    output_path: Option<PathBuf>,
) -> Result<VerifyStats, VerifyError> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let buf_reader = BufReader::new(file);
    
    /* Determine actual output path if outputting */
    let actual_output_path = output_path.map(|p| {
        if p.as_os_str().is_empty() {
            generate_clean_output_path(path)
        } else {
            p
        }
    });
    
    if verbose {
        println!("Verifying solcap file: {}", path.display());
        println!("File size: {} bytes ({:.2} MB)", file_size, file_size as f64 / (1024.0 * 1024.0));
        if let Some(ref out) = actual_output_path {
            println!("Output file: {}", out.display());
        }
        println!("\nStarting verification...\n");
    }

    /* Open output file if needed */
    let mut writer: Option<BufWriter<File>> = if let Some(ref out_path) = actual_output_path {
        let output_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out_path)?;
        Some(BufWriter::new(output_file))
    } else {
        None
    };

    let mut solcap = SolcapReader::with_buffer_size(buf_reader, DEFAULT_BUFFER_SIZE)?;
    let mut stats = VerifyStats::default();
    let mut header_state = HeaderState::new();
    
    /* Use inner reader for raw block access */
    let reader = solcap.inner_mut();
    
    loop {
        let position = reader.position() as u64;
        let result = reader.next();
        
        match result {
            Ok((offset, block)) => {
                stats.total_bytes += offset as u64;
                
                /* Validate the block using shared utility */
                let validation = validate_block(&block, &mut header_state, position);
                
                /* Drop block to release borrow before accessing reader.data() */
                drop(block);
                
                match validation {
                    Ok(block_validation) => {
                        /* Write valid block to output if enabled */
                        if let Some(ref mut w) = writer {
                            let raw_data = reader.data();
                            let data_slice = &raw_data[..offset];
                            w.write_all(data_slice)?;
                            stats.blocks_kept += 1;
                        }
                        
                        /* Update stats based on validation result */
                        match block_validation {
                            BlockValidation::SectionHeader => {
                                if verbose {
                                    println!("[0x{:08x}] Section Header Block ✓", position);
                                }
                            }
                            BlockValidation::InterfaceDescription => {
                                if verbose {
                                    println!("[0x{:08x}] Interface Description Block ✓", position);
                                }
                            }
                            BlockValidation::EnhancedPacket { block_type, slot, txn_idx, payload_size } => {
                                /* Deep validation of EPB payload */
                                if let Err((msg, off)) = validate_epb_payload(block_type, payload_size, position) {
                                    if writer.is_some() {
                                        /* In cleanup mode, just record the failure and stop */
                                        stats.failure_reason = Some(msg);
                                        stats.failure_offset = Some(off);
                                        break;
                                    } else {
                                        return Err(VerifyError::InvalidBlock(msg, off));
                                    }
                                }
                                
                                /* Update message type counts */
                                match block_type {
                                    SOLCAP_WRITE_ACCOUNT => {
                                        stats.account_update_count += 1;
                                        if verbose && stats.account_update_count == 1 {
                                            println!("[0x{:08x}] First Account Update (slot {}, txn_idx {})", position, slot, txn_idx);
                                        }
                                    }
                                    SOLCAP_WRITE_BANK_PREIMAGE => {
                                        stats.bank_preimage_count += 1;
                                        if verbose && stats.bank_preimage_count == 1 {
                                            println!("[0x{:08x}] First Bank Preimage (slot {})", position, slot);
                                        }
                                    }
                                    SOLCAP_STAKE_ACCOUNT_PAYOUT => {
                                        stats.stake_account_payout_count += 1;
                                        if verbose && stats.stake_account_payout_count == 1 {
                                            println!("[0x{:08x}] First Stake Account Payout (slot {})", position, slot);
                                        }
                                    }
                                    SOLCAP_STAKE_REWARD_EVENT => {
                                        stats.stake_reward_event_count += 1;
                                        if verbose && stats.stake_reward_event_count == 1 {
                                            println!("[0x{:08x}] First Stake Reward Event (slot {})", position, slot);
                                        }
                                    }
                                    SOLCAP_STAKE_REWARDS_BEGIN => {
                                        stats.stake_rewards_begin_count += 1;
                                        if verbose && stats.stake_rewards_begin_count == 1 {
                                            println!("[0x{:08x}] First Stake Rewards Begin (slot {})", position, slot);
                                        }
                                    }
                                    _ => {}
                                }
                                
                                stats.epb_count += 1;
                                if verbose && stats.epb_count % 1000 == 0 {
                                    println!("  ... processed {} EPB blocks", stats.epb_count);
                                }
                            }
                            BlockValidation::Other => {
                                if verbose {
                                    println!("[0x{:08x}] Other block type", position);
                                }
                            }
                        }
                        
                        reader.consume(offset);
                    }
                    Err((msg, off)) => {
                        if writer.is_some() {
                            /* In cleanup mode, record failure and stop writing */
                            stats.failure_reason = Some(msg);
                            stats.failure_offset = Some(off);
                            if verbose {
                                println!("\n✗ Invalid block at offset 0x{:08x}, truncating output here", off);
                            }
                            break;
                        } else {
                            return Err(VerifyError::InvalidBlock(msg, off));
                        }
                    }
                }
            }
            Err(pcap_parser::PcapError::Eof) => {
                if verbose && writer.is_some() {
                    println!("\n✓ Reached end of file normally");
                }
                break;
            }
            Err(pcap_parser::PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    if writer.is_some() {
                        stats.failure_reason = Some("Incomplete block at end of file".to_string());
                        stats.failure_offset = Some(position);
                        if verbose {
                            println!("\n✗ Incomplete block at offset 0x{:08x}, truncating here", position);
                        }
                    }
                    break;
                }
                continue;
            }
            Err(pcap_parser::PcapError::BufferTooSmall) => {
                let current_size = reader.data().len();
                let new_size = current_size * 2;
                if !reader.grow(new_size) {
                    if writer.is_some() {
                        stats.failure_reason = Some("Block too large to process".to_string());
                        stats.failure_offset = Some(position);
                        break;
                    } else {
                        return Err(VerifyError::MalformedBlock("Block too large".into(), position));
                    }
                }
                if reader.refill().is_err() {
                    if writer.is_some() {
                        stats.failure_reason = Some("Incomplete block after buffer growth".to_string());
                        stats.failure_offset = Some(position);
                    }
                    break;
                }
                continue;
            }
            Err(pcap_parser::PcapError::UnexpectedEof) => {
                if writer.is_some() {
                    stats.failure_reason = Some("Unexpected EOF encountered".to_string());
                    stats.failure_offset = Some(position);
                    if verbose {
                        println!("\n✗ Unexpected EOF at offset 0x{:08x}, truncating here", position);
                    }
                    break;
                } else {
                    let msg = if stats.epb_count > 0 {
                        format!("Unexpected EOF after {} blocks", stats.epb_count)
                    } else {
                        "File appears truncated".into()
                    };
                    return Err(VerifyError::MalformedBlock(msg, position));
                }
            }
            Err(e) => {
                if writer.is_some() {
                    stats.failure_reason = Some(format!("Parsing error: {:?}", e));
                    stats.failure_offset = Some(position);
                    break;
                } else {
                    return Err(VerifyError::PcapError(format!("{:?}", e)));
                }
            }
        }
    }

    /* Flush and close writer if present */
    if let Some(mut w) = writer {
        w.flush()?;
    }

    /* Final validation (only fail in verify-only mode) */
    if !header_state.section_header_found {
        if actual_output_path.is_none() {
            return Err(VerifyError::MissingSectionHeader);
        }
    }
    if !header_state.idb_found {
        if actual_output_path.is_none() {
            return Err(VerifyError::MissingInterfaceDescription);
        }
    }

    stats.section_header_found = header_state.section_header_found;
    stats.idb_found = header_state.idb_found;
    stats.output_path = actual_output_path;
    
    if verbose {
        stats.print_summary(verbose);
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_stats_creation() {
        let stats = VerifyStats::default();
        assert_eq!(stats.epb_count, 0);
        assert_eq!(stats.account_update_count, 0);
        assert_eq!(stats.bank_preimage_count, 0);
    }
    
    #[test]
    fn test_generate_clean_output_path() {
        let input = Path::new("/path/to/file.solcap");
        let output = generate_clean_output_path(input);
        assert_eq!(output, Path::new("/path/to/file_clean.solcap"));
        
        let input = Path::new("file.solcap");
        let output = generate_clean_output_path(input);
        assert_eq!(output, Path::new("file_clean.solcap"));
    }
}
