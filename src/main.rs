use std::fs;
use std::{
    collections::HashMap,
    path::PathBuf,
};

use anyhow::Context;
use structopt::StructOpt;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
};

mod types;
pub use types::*;
mod data;
mod tests;
mod templates;
pub mod plan;
mod progress_bar;

pub mod sop;
pub use sop::Sop;

/// Maximum size of artifacts included in the results.
pub const MAXIMUM_ARTIFACT_SIZE: usize = 50_000;

/// Test suite configuration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    drivers: Vec<Driver>,
    #[serde(default)]
    rlimits: std::collections::HashMap<String, u64>,
}

/// A driver configuration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Driver {
    path: String,
    #[serde(default)]
    env: std::collections::HashMap<String, String>,
}

impl Config {
    fn set_rlimits(&self) -> Result<()> {
        for (key, &value) in self.rlimits.iter() {
            match key.as_str() {
                "DATA" => rlimit::RLimit::DATA.set(value, value)?,
                _ => return
                    Err(anyhow::anyhow!("Unknown limit {:?}", key)),
            }
        }
        Ok(())
    }

    fn implementations(&self, env_override: HashMap<String, String>)
                       -> Result<Vec<crate::Sop>>
    {
        let mut r: Vec<crate::Sop> = Vec::new();
        for d in self.drivers.iter() {
            let mut env = d.env.clone();
            for (k, v) in env_override.iter() {
                env.insert(k.into(), v.into());
            }
            r.push(sop::Sop::with_env(&d.path, env)
                   .context("Creating sop backend")?);
        }
        Ok(r)
    }
}

#[derive(Debug, StructOpt)]
#[structopt(about = "The OpenPGP Interoperability Test Suite")]
pub struct Cli {
    /// Select config file to use.
    #[structopt(long, default_value = "config.json")]
    config: PathBuf,

    /// Read results from a JSON file instead of running the tests.
    #[structopt(long)]
    json_in: Option<PathBuf>,

    /// Prunes the tests, retaining those matching the given regular
    /// expression.
    #[structopt(long)]
    retain_tests: Option<String>,

    /// Write results to a JSON file.
    #[structopt(long)]
    json_out: Option<PathBuf>,

    /// Write the results to a HTML file.
    #[structopt(long)]
    html_out: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::from_args();

    if cli.json_out.is_none() && cli.html_out.is_none() {
        return
            Err(anyhow::anyhow!("Neither --json-out nor --html-out is given."));
    }

    let retain_tests = if let Some(r) = cli.retain_tests.as_ref() {
        Some(regex::RegexBuilder::new(r).case_insensitive(true).build()?)
    } else {
        None
    };

    let results = if let Some(p) = cli.json_in.as_ref() {
        serde_json::from_reader(fs::File::open(p)?)?
        // XXX prune results
    } else {
        // Create a common temporary directory.  We will clean this
        // up, so that even if SOP implementations fail to do so
        // (e.g. because they crash), all resources will be reclaimed
        // (notably, this should prevent gpg-agents from hanging
        // around).
        let tmpdir = tempfile::TempDir::new()?;

        let c: Config =
            serde_json::from_reader(
                fs::File::open(cli.config).context("Opening config file")?
            ).context("Reading config file")?;
        c.set_rlimits().context("Setting resource limits")?;
        let implementations = c.implementations(
            vec![
                ("TMPDIR".to_string(),
                 tmpdir.path().to_str().unwrap().to_string())
            ].into_iter().collect())
            .context("Setting up implementations")?;

        eprintln!("Configured engines:");
        for i in implementations.iter() {
            eprintln!("  - {}",
                      i.version().context(format!("Could not run {:?}", i))?);
        }

        let mut plan = tests::TestPlan::new(&c);
        tests::schedule(&mut plan)?;

        if let Some(r) = retain_tests {
            plan.retain_tests(|t| {
                r.is_match(&t.title())
                    || r.is_match(&t.description())
            });
        }

        plan.run(&implementations[..])?
    };

    if let Some(p) = cli.json_out.as_ref() {
        let mut sink = fs::File::create(p)?;
        serde_json::to_writer_pretty(&mut sink, &results)?;
    }

    if let Some(p) = cli.html_out.as_ref() {
        use std::io::Write;
        use templates::{Report, Renderable};

        let mut sink = fs::File::create(p)?;
        write!(sink, "{}", Report::new(results)?.render()?)?;
    }

    Ok(())
}
