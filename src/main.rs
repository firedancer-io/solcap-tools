use clap::{Arg, Command};
use solcap_tools::tools::{print_solcap_info, diff_solcap, explore_solcap, scan_solcap, verify_solcap, cleanup_solcap, coalesce_solcap};

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
                        .help("Verbosity level (1-4): 1=bank hash only, 2=full preimage, 3=+account counts, 4=+account details")
                        .default_value("2")
                        .value_parser(clap::value_parser!(u8).range(1..=4)),
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
            Command::new("explore")
                .about("Interactively explore a solcap file")
                .arg(
                    Arg::new("file")
                        .value_name("FILE")
                        .help("The solcap file to explore")
                        .required(true)
                        .index(1),
                )
        )
        .subcommand(
            Command::new("scan")
                .about("Interactively scan and compare two solcap files or bank_hash_details directories")
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
                .about("Verify that a solcap file or directory of solcap files is correctly formatted")
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
        )
        .subcommand(
            Command::new("cleanup")
                .about("Clean up a corrupted solcap file by removing incomplete/malformed blocks")
                .arg(
                    Arg::new("file")
                        .value_name("FILE")
                        .help("The solcap file to clean up")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .action(clap::ArgAction::SetTrue)
                        .help("Enable verbose output showing detailed cleanup process"),
                )
        )
        .subcommand(
            Command::new("coalesce")
                .about("Merge multiple solcap files into a single file, ordered by modification time")
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
                        .help("Output file path (default: coalesced.solcap)"),
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
        Some(("explore", sub_matches)) => {
            if let Some(file) = sub_matches.get_one::<String>("file") {
                if let Err(e) = explore_solcap(file) {
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("scan", sub_matches)) => {
            if let (Some(path1), Some(path2)) = (
                sub_matches.get_one::<String>("path1"),
                sub_matches.get_one::<String>("path2"),
            ) {
                if let Err(e) = scan_solcap(path1, path2) {
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("verify", sub_matches)) => {
            if let Some(file) = sub_matches.get_one::<String>("file") {
                let verbose = sub_matches.get_flag("verbose");
                match verify_solcap(file, verbose) {
                    Ok(_stats) => {
                        // Success message is printed by verify_solcap when verbose
                        if !verbose {
                            println!("✓ File is valid");
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
        Some(("cleanup", sub_matches)) => {
            if let Some(file) = sub_matches.get_one::<String>("file") {
                let verbose = sub_matches.get_flag("verbose");
                match cleanup_solcap(file, verbose) {
                    Ok(_stats) => {
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("✗ Cleanup failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        Some(("coalesce", sub_matches)) => {
            let files: Vec<String> = sub_matches
                .get_many::<String>("files")
                .unwrap()
                .map(|s| s.to_string())
                .collect();
            let output = sub_matches.get_one::<String>("output").cloned();
            let verbose = sub_matches.get_flag("verbose");
            
            match coalesce_solcap(&files, output, verbose) {
                Ok(_stats) => {
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("✗ Coalesce failed: {}", e);
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
            println!("  solcap-tools explore input.solcap");
            println!("  solcap-tools scan file1.solcap file2.solcap");
            println!("  solcap-tools verify input.solcap");
            println!("  solcap-tools verify /path/to/directory");
            println!("  solcap-tools cleanup corrupted.solcap");
            println!("  solcap-tools coalesce file1.solcap file2.solcap file3.solcap -o merged.solcap");
        }
    }
}
