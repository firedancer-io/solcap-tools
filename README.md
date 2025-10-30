# Solcap Tools

A Rust-based toolkit for parsing, analyzing, and visualizing solcap files. Solcap is a portable file format for capturing Solana runtime data, built on top of the pcapng format.

## Features

- **Fast Binary Parser**: Efficiently reads solcap files using zero-copy techniques
- **Multiple Visualization Modes**: Summary, table, detailed, and compact views
- **Account History Tracking**: Track changes to specific accounts across slots
- **Slot-based Analysis**: Filter and analyze data by slot number
- **Binary Format Compatibility**: Handles the complete solcap v2 format including:
  - Account updates with metadata and data
  - Bank preimages with hashes and signature counts
  - Proper handling of packed C structs and alignment

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo

### Build from Source

```bash
git clone <repository>
cd solcap-tools
cargo build --release
```

The binary will be available at `target/release/solcap-tools`.

## Usage

### Verify Solcap File Format

The `verify` subcommand validates the structure and integrity of a solcap file or directory of solcap files:

```bash
# Quick verification of a single file (minimal output)
solcap-tools verify <file.solcap>

# Verbose verification of a single file (shows detailed information)
solcap-tools verify <file.solcap> --verbose

# Batch verification of all .solcap files in a directory
solcap-tools verify /path/to/directory

# Batch verification with verbose output for each file
solcap-tools verify /path/to/directory --verbose
```

**What it checks:**
- Section Header Block presence and magic number (0x0A0D0D0A)
- Interface Description Block presence and link type (147)
- All following blocks are Enhanced Packet Blocks (EPB)
- Each EPB has a valid internal chunk header
- Internal chunk headers have valid message type signatures
- Data blocks have sufficient size for their declared content
- No malformed or truncated blocks

**Output:**
```bash
# Success (non-verbose)
✓ File is valid

# Success (verbose)
Verifying solcap file: fd2.solcap
File size: 12345678 bytes (11.77 MB)

Starting verification...

[0x00000000] Section Header Block
  ✓ Valid block type: 0x0a0d0d0a
  ✓ Version: 1.1
[0x00000020] Interface Description Block
  ✓ Valid link type: 147
  ✓ Snap length: 0
[0x00000034] First Enhanced Packet Block
  ✓ Account Update (slot 123456, txn_idx 0)
  ... processed 1000 EPB blocks

✓ Verification completed successfully!

File Statistics:
  Section Header:       ✓
  Interface Desc Block: ✓
  EPB Blocks:           1000

Message Types:
  Account Updates:      950
  Bank Preimages:       50
  Account Data:         0
  Stake Rewards:        0
  Other Messages:       0

Total File Size:        12345678 bytes (11.77 MB)
```

**Batch Verification Output:**
```bash
Scanning directory: /path/to/solcaps

Found 3 .solcap file(s) to verify

================================================================================

[1/3] Verifying: file1.solcap
--------------------------------------------------------------------------------
✓ Valid (1000 EPB blocks, 11.77 MB)

[2/3] Verifying: file2.solcap
--------------------------------------------------------------------------------
✓ Valid (850 EPB blocks, 9.23 MB)

[3/3] Verifying: file3.solcap
--------------------------------------------------------------------------------
✗ Failed: Missing Section Header Block

================================================================================

📊 BATCH VERIFICATION SUMMARY

Total Files:          3
Successful:           2 ✓
Failed:               1 ✗

Failed Files:
  ✗ file3.solcap: Missing Section Header Block

Aggregate Statistics (successful files only):
  Total EPB Blocks:     1850
  Account Updates:      1800
  Bank Preimages:       50
  Account Data:         0
  Stake Rewards:        0
  Total Data Size:      22020096 bytes (21.00 MB)

================================================================================
```

**Use cases:**
- Validate files after transfer or generation
- Debug file corruption issues
- Verify file format compliance
- Quick sanity check before processing large files
- Batch validation of multiple capture files in a directory
- CI/CD pipeline verification of generated solcap files

### Print Solcap Information

The `print` subcommand displays information about a solcap file:

```bash
# Basic printing (bank hash and preimage info)
solcap-tools print <file.solcap>

# Verbose output levels (1-4)
solcap-tools print <file.solcap> -v 1  # Bank hash only
solcap-tools print <file.solcap> -v 2  # Full preimage
solcap-tools print <file.solcap> -v 3  # + final accounts
solcap-tools print <file.solcap> -v 4  # + account data

# Filter by slot range
solcap-tools print <file.solcap> --start-slot 100 --end-slot 200

# Show all account updates (not just final state)
solcap-tools print <file.solcap> --show-all-updates
```

### Compare Two Solcap Files

The `diff` subcommand compares two solcap files or bank_hash_details directories:

```bash
# Compare two solcap files
solcap-tools diff file1.solcap file2.solcap

# Compare with different verbosity levels
solcap-tools diff file1.solcap file2.solcap -v 3

# Filter comparison by slot range
solcap-tools diff file1.solcap file2.solcap --start-slot 100 --end-slot 200

# Compare bank_hash_details directories
solcap-tools diff /path/to/bhd1 /path/to/bhd2
```

### Interactive Explorer

The `explore` subcommand provides an interactive terminal UI to navigate through a solcap file:

```bash
solcap-tools explore <file.solcap>
```

### Interactive Scanner

The `scan` subcommand provides an interactive comparison interface for two solcap files:

```bash
solcap-tools scan file1.solcap file2.solcap
```

### Cleanup Corrupted Files

The `cleanup` subcommand salvages valid data from corrupted/incomplete solcap files:

```bash
# Clean up a corrupted file (creates filename_clean.solcap)
solcap-tools cleanup corrupted.solcap

# Verbose cleanup showing detailed process
solcap-tools cleanup corrupted.solcap --verbose
```

**How it works:**
- Reads through the file block by block
- Copies all valid blocks to a new `_clean.solcap` file
- Stops when it encounters the first invalid/incomplete block
- Ensures the output file has required headers (Section Header, IDB)
- Original file is not modified

**Output example:**
```bash
Cleaning up solcap file: corrupted.solcap
Output file: corrupted_clean.solcap

Starting cleanup process...

✓ Cleanup completed successfully!

Original File:  corrupted.solcap
Cleaned File:   corrupted_clean.solcap

Statistics:
  Original Size:    100000000 bytes (95.37 MB)
  Cleaned Size:     99500000 bytes (94.89 MB)
  Blocks Kept:      48451
  Blocks Removed:   1
  Data Removed:     500000 bytes (0.48 MB)
```

**Use cases:**
- Recover data from files with incomplete writes
- Remove truncated blocks at end of file
- Fix files with unexpected EOF errors
- Prepare corrupted files for analysis tools
- Salvage as much data as possible from damaged captures

### Coalesce Multiple Files

The `coalesce` subcommand merges multiple solcap files into a single file:

```bash
# Merge files (automatically ordered by modification time, oldest first)
solcap-tools coalesce file1.solcap file2.solcap file3.solcap

# Specify custom output path
solcap-tools coalesce file1.solcap file2.solcap -o merged.solcap

# Verbose mode showing detailed merge process
solcap-tools coalesce *.solcap -o combined.solcap --verbose
```

**How it works:**
- Automatically orders input files by modification time (oldest to newest)
- Creates a single output file with:
  - One Section Header Block (from first file)
  - One Interface Description Block (from first file)
  - All EPB blocks from all files in temporal order
- Skips duplicate headers from subsequent files
- Maintains block order within each file

**Output example:**
```bash
Coalescing 3 file(s) into: merged.solcap

  ✓ file1.solcap - 10000 EPB blocks
  ✓ file2.solcap - 15000 EPB blocks
  ✓ file3.solcap - 8500 EPB blocks

✓ Coalescing completed successfully!

Output File:  merged.solcap

Statistics:
  Input Files:      3
  Total EPB Blocks: 33500
  Output Size:      125829376 bytes (120.00 MB)
```

**Verbose output shows:**
- Files in temporal order (oldest to newest)
- Which headers are being used vs. skipped
- Progress for each file being processed
- Warning messages for any skipped blocks

**Use cases:**
- Merge multiple capture sessions into one file
- Combine split/rotated capture files
- Create a single file for analysis from multiple sources
- Consolidate captures by time period
- Prepare data for tools that expect a single input file

## Solcap File Format

Solcap files follow the pcapng (packet capture next generation) format with custom payload types:

### File Structure

```
[Section Header Block]           # PCAPNG file header
[Interface Description Block]    # PCAPNG interface info
[Enhanced Packet Block #1]       # Contains solcap message
  - EPB Header
  - Internal Chunk Header        # slot, txn_idx, message type
  - Message Payload              # Account update or bank preimage
  - Footer
[Enhanced Packet Block #2]
  ...
```

### Message Types

1. **Account Update (Type 1)**
   - Public key (32 bytes)
   - Account metadata:
     - Lamports (8 bytes)
     - Rent epoch (8 bytes)
     - Owner pubkey (32 bytes)
     - Executable flag (1 byte)
     - Padding (3 bytes)
   - Data size (8 bytes)
   - Account data (variable length)

2. **Bank Preimage (Type 6)**
   - Bank hash
   - Previous bank hash
   - Account delta hash
   - Accounts LT hash checksum
   - PoH hash
   - Signature count

### Binary Format Details

- All integers are little-endian
- Structs are C-packed with explicit padding
- Account metadata size: 52 bytes
- Account update header size: 92 bytes (key + metadata + data_sz)

## Architecture

```
solcap-tools/
├── src/
│   ├── parser/          # Binary format parsing
│   │   ├── format.rs    # Struct definitions matching C headers
│   │   └── reader.rs    # File reading and parsing logic
│   ├── model/           # Data structures
│   │   └── state.rs     # In-memory representation of parsed data
│   ├── analyzer/        # Analysis logic
│   │   └── state.rs     # Statistics and querying
│   ├── ui/              # Visualization
│   │   └── printer.rs   # Pretty printing functions
│   ├── lib.rs           # Library entry point
│   └── main.rs          # CLI application
└── Cargo.toml
```

## Performance

- Parsing: ~1-2 GB/s depending on message density
- Memory usage: Loads entire capture into memory for analysis
- For very large files (>1GB), consider using streaming mode (future feature)

## Development

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

### Code Organization

- **Parser**: Low-level binary parsing, no business logic
- **Model**: Domain objects and data structures
- **Analyzer**: High-level analysis and statistics
- **UI**: Presentation layer, multiple output formats

## Future Enhancements

- [x] Interactive TUI mode with navigation (explore/scan commands)
- [x] Diff tool to compare two captures
- [x] File format verification tool
- [x] Batch verification for multiple files
- [x] Repair/cleanup tool for corrupted files
- [x] Coalesce/merge tool for combining multiple files
- [ ] Streaming parser for large files
- [ ] Export to other formats (JSON, CSV)
- [ ] Filter by account, owner, or other criteria
- [ ] Support for additional solcap message types
- [ ] Performance profiling and optimization

## Contributing

Contributions are welcome! Please ensure:
- Code follows Rust idioms and best practices
- New features include tests
- Public APIs are documented
- Changes don't break binary format compatibility

## License

[Add license information]

## Credits

Built for the Firedancer project to analyze Solana validator capture data.
