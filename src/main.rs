use clap::{Arg, Command};
use solcap_tools::tools::{print_solcap_info, diff_solcap, compare_solcap, verify_solcap, combine_solcap};

fn main() {
    let matches = Command::new("solcap-tools")
        .version("0.1.0")
        .author("Firedancer Team")
        .about("Tools for analyzing and visualizing solcap files")
        .subcommand(
            Command::new("print")
                .about("Print information about a solcap file")
                .arg(
                    Arg::new("file")
                        .value_name("FILE")
                        .help("The solcap file to analyze")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("verbosity")
                        .short('v')
                        .long("verbosity")
                        .value_name("LEVEL")
                        .help("Verbosity level (1-4): 1=bank hash only, 2=full preimage, 3=+final accounts, 4=+account data")
                        .default_value("2")
                        .value_parser(clap::value_parser!(u8).range(1..=4)),
                )
                .arg(
                    Arg::new("start-slot")
                        .long("start-slot")
                        .value_name("SLOT")
                        .help("Starting slot to display (inclusive)")
                        .value_parser(clap::value_parser!(u32)),
                )
                .arg(
                    Arg::new("end-slot")
                        .long("end-slot")
                        .value_name("SLOT")
                        .help("Ending slot to display (inclusive)")
                        .value_parser(clap::value_parser!(u32)),
                )
                .arg(
                    Arg::new("show-all-updates")
                        .long("show-all-updates")
                        .action(clap::ArgAction::SetTrue)
                        .help("Show all account updates instead of just final updates (for debugging ordering issues)"),
                )
        )
        .subcommand(
            Command::new("diff")
                .about("Compare two solcap files or bank_hash_details directories")
                .arg(
                    Arg::new("path1")
                        .value_name("PATH1")
                        .help("First path (solcap file or bank_hash_details directory)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("path2")
                        .value_name("PATH2")
                        .help("Second path (solcap file or bank_hash_details directory)")
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::new("verbosity")
                        .short('v')
                        .long("verbosity")
                        .value_name("LEVEL")
                        .help("Verbosity level (1-5): 1=bank hash only, 2=full preimage, 3=+account counts, 4=+account details, 5=+data comparison")
                        .default_value("2")
                        .value_parser(clap::value_parser!(u8).range(1..=5)),
                )
                .arg(
                    Arg::new("start-slot")
                        .long("start-slot")
                        .value_name("SLOT")
                        .help("Starting slot to compare (inclusive)")
                        .value_parser(clap::value_parser!(u32)),
                )
                .arg(
                    Arg::new("end-slot")
                        .long("end-slot")
                        .value_name("SLOT")
                        .help("Ending slot to compare (inclusive)")
                        .value_parser(clap::value_parser!(u32)),
                )
        )
        .subcommand(
            Command::new("compare")
                .about("Interactively compare two solcap files or bank_hash_details directories")
                .arg(
                    Arg::new("path1")
                        .value_name("PATH1")
                        .help("First path (solcap file or bank_hash_details directory)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("path2")
                        .value_name("PATH2")
                        .help("Second path (solcap file or bank_hash_details directory)")
                        .required(true)
                        .index(2),
                )
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a solcap file is correctly formatted. Use -o to output a cleaned version.")
                .arg(
                    Arg::new("file")
                        .value_name("PATH")
                        .help("The solcap file or directory to verify (directory: verifies all .solcap files)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .action(clap::ArgAction::SetTrue)
                        .help("Enable verbose output with detailed verification information"),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("OUTPUT")
                        .num_args(0..=1)
                        .default_missing_value("")
                        .help("Output cleaned solcap file (removes invalid/incomplete blocks). If no path given, outputs to <input>_clean.solcap"),
                )
        )
        .subcommand(
            Command::new("combine")
                .about("Combine multiple solcap files into a single file, ordered by modification time")
                .arg(
                    Arg::new("files")
                        .value_name("FILES")
                        .help("Solcap files to merge (will be ordered by modification time)")
                        .required(true)
                        .num_args(1..)
                        .index(1),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("OUTPUT")
                        .help("Output file path (default: combined.solcap)"),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .action(clap::ArgAction::SetTrue)
                        .help("Enable verbose output showing detailed merge process"),
                )
        )
        .get_matches();

    match matches.subcommand() {
        Some(("print", sub_matches)) => {
            if let Some(file) = sub_matches.get_one::<String>("file") {
                let verbosity = *sub_matches.get_one::<u8>("verbosity").unwrap_or(&2);
                let start_slot = sub_matches.get_one::<u32>("start-slot").copied();
                let end_slot = sub_matches.get_one::<u32>("end-slot").copied();
                let show_all_updates = sub_matches.get_flag("show-all-updates");
                if let Err(e) = print_solcap_info(file, verbosity, start_slot, end_slot, show_all_updates) {
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("diff", sub_matches)) => {
            if let (Some(path1), Some(path2)) = (
                sub_matches.get_one::<String>("path1"),
                sub_matches.get_one::<String>("path2"),
            ) {
                let verbosity = *sub_matches.get_one::<u8>("verbosity").unwrap_or(&2);
                let start_slot = sub_matches.get_one::<u32>("start-slot").copied();
                let end_slot = sub_matches.get_one::<u32>("end-slot").copied();
                if let Err(e) = diff_solcap(path1, path2, verbosity, start_slot, end_slot) {
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("compare", sub_matches)) => {
            if let (Some(path1), Some(path2)) = (
                sub_matches.get_one::<String>("path1"),
                sub_matches.get_one::<String>("path2"),
            ) {
                if let Err(e) = compare_solcap(path1, path2) {
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("verify", sub_matches)) => {
            if let Some(file) = sub_matches.get_one::<String>("file") {
                let verbose = sub_matches.get_flag("verbose");
                let output = sub_matches.get_one::<String>("output").cloned();
                
                match verify_solcap(file, verbose, output.as_ref()) {
                    Ok(stats) => {
                        if !verbose {
                            if stats.output_path.is_some() {
                                println!("✓ File verified and cleaned output written");
                            } else {
                                println!("✓ File is valid");
                            }
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("✗ Verification failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        Some(("combine", sub_matches)) => {
            let input_args: Vec<String> = sub_matches
                .get_many::<String>("files")
                .unwrap()
                .map(|s| s.to_string())
                .collect();
            let output = sub_matches.get_one::<String>("output").cloned();
            let verbose = sub_matches.get_flag("verbose");
            
            /* Expand directories to find .solcap files */
            let mut files = Vec::new();
            for path_str in input_args {
                let path = std::path::Path::new(&path_str);
                if path.is_dir() {
                    /* Collect all .solcap files in the directory */
                    match std::fs::read_dir(path) {
                        Ok(entries) => {
                            for entry in entries {
                                if let Ok(entry) = entry {
                                    let entry_path = entry.path();
                                    if entry_path.is_file() {
                                        if let Some(ext) = entry_path.extension() {
                                            if ext == "solcap" {
                                                files.push(entry_path.to_string_lossy().to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Error reading directory {}: {}", path_str, e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    files.push(path_str);
                }
            }
            
            if files.is_empty() {
                eprintln!("✗ No .solcap files found in the specified paths");
                std::process::exit(1);
            }
            
            match combine_solcap(&files, output, verbose) {
                Ok(_stats) => {
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("✗ Combine failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("solcap-tools v0.1.0");
            println!("Use --help for usage information");
            println!("\nExamples:");
            println!("  solcap-tools print input.solcap");
            println!("  solcap-tools diff file1.solcap file2.solcap");
            println!("  solcap-tools compare file1.solcap file2.solcap");
            println!("  solcap-tools verify input.solcap");
            println!("  solcap-tools verify input.solcap -o              # output to input_clean.solcap");
            println!("  solcap-tools verify input.solcap -o cleaned.solcap");
            println!("  solcap-tools verify /path/to/directory");
            println!("  solcap-tools combine file1.solcap file2.solcap -o merged.solcap");
        }
    }
}
