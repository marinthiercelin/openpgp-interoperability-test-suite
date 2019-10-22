use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    // Generate the 'cargo:' key output
    generate_cargo_keys(ConstantsFlags::all())
        .expect("Unable to generate the cargo keys!");

    include_test_data().unwrap();
}

/// Builds the index of the test data for use with the `::tests`
/// module.
fn include_test_data() -> io::Result<()> {
    let cwd = env::current_dir()?;
    let mut sink = fs::File::create(
        PathBuf::from(env::var_os("OUT_DIR").unwrap())
            .join("data.index.rs.inc")).unwrap();

    writeln!(&mut sink, "{{")?;
    let mut dirs = vec![PathBuf::from("data")];
    while let Some(dir) = dirs.pop() {
        println!("rerun-if-changed={}", dir.to_str().unwrap());
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                writeln!(
                    &mut sink, "    add!({:?}, {:?});",
                    path.components().skip(1)
                        .map(|c| c.as_os_str().to_str().expect("valid UTF-8"))
                        .collect::<Vec<_>>().join("/"),
                    cwd.join(path))?;
            } else if path.is_dir() {
                dirs.push(path.clone());
            }
        }
    }
    writeln!(&mut sink, "}}")?;
    Ok(())
}
