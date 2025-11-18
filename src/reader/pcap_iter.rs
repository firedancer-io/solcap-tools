use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader};
use pcap_parser::traits::PcapReaderIterator;
use std::io::Read;

/// Default buffer size for PCAP reading (64MB)
/// This is large enough to handle very large account data blocks in solcap files
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Errors that can occur during PCAP iteration
#[derive(Debug)]
pub enum PcapIterError {
    /// IO error when reading
    IoError(std::io::Error),
    /// PCAP parsing error
    PcapError(String),
    /// Invalid format
    InvalidFormat(String),
    /// Incomplete data
    IncompleteData(String),
}

impl From<std::io::Error> for PcapIterError {
    fn from(err: std::io::Error) -> Self {
        PcapIterError::IoError(err)
    }
}

impl<I: std::fmt::Debug> From<PcapError<I>> for PcapIterError {
    fn from(err: PcapError<I>) -> Self {
        PcapIterError::PcapError(format!("{:?}", err))
    }
}

impl std::fmt::Display for PcapIterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapIterError::IoError(e) => write!(f, "IO error: {}", e),
            PcapIterError::PcapError(e) => write!(f, "PCAP parsing error: {}", e),
            PcapIterError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            PcapIterError::IncompleteData(msg) => write!(f, "Incomplete data: {}", msg),
        }
    }
}

impl std::error::Error for PcapIterError {}

/// State tracked during PCAP iteration
#[derive(Debug, Default)]
pub struct IterationState {
    /// Current byte offset in the file
    pub current_offset: u64,
    /// Whether Section Header Block has been found
    pub section_found: bool,
    /// Whether Interface Description Block has been found
    pub idb_found: bool,
    /// Whether any Enhanced Packet Block has been seen
    pub epb_seen: bool,
    /// Number of blocks processed
    pub blocks_processed: u64,
}

/// Trait for handling blocks during iteration
/// Implement this trait to customize block processing behavior
pub trait BlockHandler {
    /// Error type returned by this handler
    type Error: From<PcapIterError>;

    /// Called when a block is successfully parsed
    /// 
    /// # Arguments
    /// * `block` - The parsed PCAP block
    /// * `state` - Current iteration state (mutable reference)
    /// * `offset` - Byte offset of this block in the file
    /// 
    /// # Note on Raw Data
    /// For handlers that need raw bytes (e.g., for writing operations), the raw data
    /// can be accessed via `iterator.raw_data()[..offset]` before calling `consume()`.
    /// However, due to Rust's borrow checker limitations, this must be done outside
    /// the handler callback. For most use cases, the parsed `block` contains all
    /// necessary information.
    /// 
    /// # Returns
    /// `Ok(())` to continue iteration, or an error to stop iteration
    fn handle_block(
        &mut self,
        block: &PcapBlockOwned,
        state: &mut IterationState,
        offset: usize,
    ) -> Result<(), Self::Error>;

    /// Called when EOF is reached (normal end of file)
    /// Default implementation does nothing
    fn handle_eof(&mut self, _state: &mut IterationState) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when an incomplete block is encountered
    /// Return `true` to try refilling the buffer, `false` to stop iteration
    /// Default implementation returns `true` to try refilling
    fn handle_incomplete(
        &mut self,
        _state: &mut IterationState,
    ) -> Result<bool, Self::Error> {
        // Default: try to refill
        Ok(true)
    }

    /// Called when buffer is too small for a block
    /// Return the new buffer size to grow to, or `None` to stop iteration
    /// Default implementation doubles the buffer size
    fn handle_buffer_too_small(
        &mut self,
        _state: &mut IterationState,
        current_size: usize,
    ) -> Result<Option<usize>, Self::Error> {
        // Default: double the buffer size
        let new_size = current_size * 2;
        Ok(Some(new_size))
    }

    /// Called when unexpected EOF is encountered
    /// Default implementation returns an error
    fn handle_unexpected_eof(
        &mut self,
        state: &mut IterationState,
    ) -> Result<(), Self::Error> {
        if state.blocks_processed > 0 {
            Err(PcapIterError::IncompleteData(
                format!("Unexpected EOF encountered (may be incomplete last block), but {} blocks were processed successfully", state.blocks_processed)
            ).into())
        } else {
            Err(PcapIterError::IncompleteData(
                "File appears to be truncated or invalid".to_string()
            ).into())
        }
    }

    /// Called when any other error occurs
    /// Default implementation converts the error
    fn handle_other_error(
        &mut self,
        _state: &mut IterationState,
        error: PcapError<impl std::fmt::Debug>,
    ) -> Result<(), Self::Error> {
        Err(PcapIterError::from(error).into())
    }
}

/// Iterator for PCAP-NG files with solcap-specific functionality
/// 
/// This wraps `PcapNGReader` and provides a convenient interface for iterating
/// through PCAP blocks with common error handling and state tracking.
pub struct PcapIterator<R: Read> {
    reader: PcapNGReader<R>,
    state: IterationState,
}

impl<R: Read> PcapIterator<R> {
    /// Create a new iterator from a Read implementation
    /// Uses the default buffer size (64MB)
    pub fn new(reader: R) -> Result<Self, PcapIterError> {
        Self::with_buffer_size(reader, DEFAULT_BUFFER_SIZE)
    }

    /// Create a new iterator with a custom buffer size
    pub fn with_buffer_size(reader: R, buffer_size: usize) -> Result<Self, PcapIterError> {
        let pcap_reader = PcapNGReader::new(buffer_size, reader)?;
        Ok(Self {
            reader: pcap_reader,
            state: IterationState::default(),
        })
    }

    /// Get a reference to the current iteration state
    pub fn state(&self) -> &IterationState {
        &self.state
    }

    /// Get a mutable reference to the current iteration state
    pub fn state_mut(&mut self) -> &mut IterationState {
        &mut self.state
    }

    /// Get a reference to the underlying PCAP reader
    pub fn reader(&self) -> &PcapNGReader<R> {
        &self.reader
    }

    /// Get a mutable reference to the underlying PCAP reader
    pub fn reader_mut(&mut self) -> &mut PcapNGReader<R> {
        &mut self.reader
    }

    /// Get the raw data buffer from the reader
    /// This is useful for writing blocks to output files
    pub fn raw_data(&self) -> &[u8] {
        self.reader.data()
    }

    /// Iterate through all blocks in the file, calling the handler for each block
    /// 
    /// This method handles all common error cases (EOF, incomplete blocks, buffer too small, etc.)
    /// and calls the appropriate handler methods.
    /// 
    /// # Arguments
    /// * `handler` - A type implementing `BlockHandler` that processes each block
    /// 
    /// # Returns
    /// `Ok(())` if iteration completed successfully, or an error from the handler
    pub fn iterate<H: BlockHandler>(&mut self, handler: &mut H) -> Result<(), H::Error> {
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let block_offset = offset;
                    
                    // Process this block
                    // Note: Handlers that need raw data should access iterator.raw_data() 
                    // before this call, but due to borrow checker limitations, we can't
                    // provide it directly in the callback. Most handlers don't need raw data.
                    self.state.blocks_processed += 1;
                    handler.handle_block(&block, &mut self.state, block_offset)?;
                    self.state.current_offset += block_offset as u64;
                    self.reader.consume(block_offset);
                }
                Err(PcapError::Eof) => {
                    handler.handle_eof(&mut self.state)?;
                    break;
                }
                Err(PcapError::Incomplete(_n)) => {
                    let should_refill = handler.handle_incomplete(&mut self.state)?;
                    if should_refill {
                        if let Err(e) = self.reader.refill() {
                            return Err(PcapIterError::from(e).into());
                        }
                    } else {
                        break;
                    }
                    continue;
                }
                Err(PcapError::BufferTooSmall) => {
                    let current_size = self.reader.data().len();
                    match handler.handle_buffer_too_small(&mut self.state, current_size)? {
                        Some(new_size) => {
                            if !self.reader.grow(new_size) {
                                return Err(PcapIterError::InvalidFormat(
                                    format!("Buffer too small (current: {}), cannot grow to {}", current_size, new_size)
                                ).into());
                            }
                            if let Err(e) = self.reader.refill() {
                                return Err(PcapIterError::from(e).into());
                            }
                        }
                        None => {
                            break;
                        }
                    }
                    continue;
                }
                Err(PcapError::UnexpectedEof) => {
                    handler.handle_unexpected_eof(&mut self.state)?;
                    break;
                }
                Err(e) => {
                    handler.handle_other_error(&mut self.state, e)?;
                    break;
                }
            }
        }
        Ok(())
    }
    
    /// Get raw data for the current block
    /// This should be called after next() but before consume()
    /// Note: This requires that the block has been consumed or the offset is known
    pub fn get_raw_data_for_offset(&self, offset: usize) -> Vec<u8> {
        self.reader.data()[..offset].to_vec()
    }

    /// Validate that required headers (Section Header and IDB) are present
    /// 
    /// This is typically called after iteration completes to ensure the file
    /// has the minimum required structure.
    pub fn validate_headers(&self) -> Result<(), PcapIterError> {
        if !self.state.section_found {
            return Err(PcapIterError::InvalidFormat(
                "No Section Header Block found".to_string(),
            ));
        }

        if !self.state.idb_found {
            return Err(PcapIterError::InvalidFormat(
                "No Interface Description Block found".to_string(),
            ));
        }

        Ok(())
    }
}

/// Convenience function to create an iterator from a file path
pub fn from_file<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<PcapIterator<std::io::BufReader<std::fs::File>>, PcapIterError> {
    use std::fs::File;
    use std::io::BufReader;
    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    PcapIterator::new(buf_reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iteration_state_default() {
        let state = IterationState::default();
        assert_eq!(state.current_offset, 0);
        assert!(!state.section_found);
        assert!(!state.idb_found);
        assert!(!state.epb_seen);
        assert_eq!(state.blocks_processed, 0);
    }
}

