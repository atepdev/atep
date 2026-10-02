//! Generate or check the ATEP test vectors.
//!
//!   atep-vectors generate <dir>   write all vectors from the fixed seeds
//!   atep-vectors check <dir>      verify every vector found under <dir>

use std::path::Path;
use std::process::ExitCode;

use atep_core::vectors;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("generate"), Some(dir)) => match vectors::write_dir(Path::new(dir)) {
            Ok(n) => {
                println!("wrote {n} files under {dir}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        (Some("check"), Some(dir)) => match vectors::check_dir(Path::new(dir)) {
            Ok(n) => {
                println!("all {n} vectors pass");
                ExitCode::SUCCESS
            }
            Err(fails) => {
                for f in &fails {
                    eprintln!("FAIL {f}");
                }
                eprintln!("{} vector(s) failed", fails.len());
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: atep-vectors generate <dir> | atep-vectors check <dir>");
            ExitCode::from(2)
        }
    }
}
