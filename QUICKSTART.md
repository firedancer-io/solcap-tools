# Solcap Tools - Quick Start Guide

## Installation

```bash
cd solcap-tools
cargo build --release
# Binary will be at: target/release/solcap-tools
```

## Common Commands

### View Summary Statistics
```bash
solcap-tools vis capture.solcap
# or
solcap-tools vis capture.solcap --summary
```

### Show Slot Table
```bash
solcap-tools vis capture.solcap --table
```

### View Specific Slot(s)
```bash
# Single slot
solcap-tools vis capture.solcap --detailed --slot 346556001

# Multiple slots
solcap-tools vis capture.solcap --detailed --slot 346556001 --slot 346556002

# Compact view (one line per slot)
solcap-tools vis capture.solcap --detailed --compact
```

### View Account Data
```bash
# Show first 64 bytes (default)
solcap-tools vis capture.solcap --detailed --slot 346556001

# Show full account data
solcap-tools vis capture.solcap --detailed --slot 346556001 --show-data

# Show first N bytes
solcap-tools vis capture.solcap --detailed --max-data-bytes 128
```

### Track Account History
```bash
solcap-tools account capture.solcap <pubkey-in-base58>

# Example:
solcap-tools account capture.solcap 4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg
```

## Output Examples

### Summary
Shows high-level statistics:
- Slot range
- Number of slots and messages
- Unique accounts
- Data sizes and averages

### Table
Columnar view of all slots:
- Slot number
- Number of account updates
- Whether bank preimage is present

### Detailed
Full information for each slot:
- All account updates with metadata
- Account addresses (base58 encoded)
- Lamports, owners, executable flags
- Account data (hex encoded)
- Bank preimages with all hashes

## Tips

1. **Large Files**: For files >1GB, start with `--summary` or `--table` to get an overview
2. **Filtering**: Use `--slot` to focus on specific slots when analyzing issues
3. **Compact Mode**: Use `--compact` when you need to see many slots quickly
4. **Account Tracking**: Use the `account` subcommand to see how an account changes over time
5. **Performance**: The release build (`cargo build --release`) is 10-20x faster than debug builds

## Format Reference

### Account Update Structure
- **Pubkey**: 32 bytes (shown as base58)
- **Lamports**: u64
- **Rent Epoch**: u64
- **Owner**: Pubkey (32 bytes, shown as base58)
- **Executable**: bool
- **Data**: Variable length bytes (shown as hex)

### Bank Preimage Structure
- **Bank Hash**: 32 bytes
- **Previous Bank Hash**: 32 bytes
- **Account Delta Hash**: 32 bytes
- **Accounts LT Hash Checksum**: 32 bytes
- **PoH Hash**: 32 bytes
- **Signature Count**: u64

All hashes are shown in base58 encoding.

## Troubleshooting

### "Invalid magic" or "Invalid format"
- Ensure the file is a valid solcap v2 file
- Check that the file hasn't been corrupted
- Verify it's not a solcap v1 file (deprecated format)

### Out of Memory
- For very large files, use `--slot` to analyze specific portions
- Consider splitting the capture into smaller files
- Future versions will support streaming mode

### Slow Performance
- Use the release build: `cargo build --release`
- Avoid `--show-data` on large captures
- Use `--compact` mode for faster display

## Getting Help

```bash
solcap-tools --help
solcap-tools vis --help
solcap-tools account --help
```

