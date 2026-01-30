# Solcap Tools

A Rust toolkit for parsing and analyzing solcap files—a portable format for capturing Solana runtime data built on pcapng.

## Usage

```bash
# Build
cargo build --release

# Print file info
solcap-tools print <file.solcap>

# Diff two files
solcap-tools diff file1.solcap file2.solcap

# Interactive comparison
solcap-tools compare file1.solcap file2.solcap

# Verify file format (optionally output cleaned version)
solcap-tools verify <file.solcap>
solcap-tools verify <file.solcap> -o cleaned.solcap

# Combine multiple files
solcap-tools combine *.solcap -o merged.solcap
```

## Structure

```
src/
├── main.rs              # CLI entry point
├── lib.rs               # Library exports
├── reader/              # Binary format parsing (solcap + agave bank_hash_details)
├── model/               # Data structures
├── tools/               # Subcommands (print, diff, compare, verify, combine)
└── utils/               # Helpers (spinners, validation)
```

## Tool Tips

If you see any errors when a tool is parsing your solcap, it is likely because your solcap is malformed. You can use the verify tool with a `-o` flag to produce a cleaned version of the solcap and try running with that

When unsure about any CLI commands `--help` may assist in providing more information