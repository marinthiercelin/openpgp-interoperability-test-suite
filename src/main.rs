use std::fmt;
use std::fs;
use std::{
    path::PathBuf,
};

use anyhow::Context;
use structopt::StructOpt;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
};

mod data;
mod tests;
mod templates;
mod plan;
mod progress_bar;

mod sop;
pub use sop::Sop;

/// Maximum size of artifacts included in the results.
pub const MAXIMUM_ARTIFACT_SIZE: usize = 50_000;

/// Backends supported by the test suite.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum Implementation {
    Sop(String),
}

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Implementation::Sop(s) => f.write_str(&s),
        }
    }
}

impl serde::Serialize for Implementation {
    fn serialize<S>(&self, serializer: S)
                    -> std::result::Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// (Backend, Version)-tuple supporting multiple versions per backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct Version {
    pub implementation: String,
    pub version: String,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.implementation, self.version)
    }
}

/// Chunks of data.
#[derive(Clone, Debug, Default)]
pub struct Data(Box<[u8]>);

impl std::ops::Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data(v.into())
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        v.to_vec().into()
    }
}

impl From<Data> for Vec<u8> {
    fn from(v: Data) -> Self {
        v.0.into()
    }
}

use serde::{Serializer, Deserializer, de::{Error as _}};
impl serde::Serialize for Data {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer
    {
        s.serialize_str(&base64::encode(self))
    }
}

impl<'de> serde::Deserialize<'de> for Data {
    fn deserialize<D>(d: D) -> std::result::Result<Data, D::Error>
    where D: Deserializer<'de>
    {
        let s = String::deserialize(d)?;
        base64::decode(s)
            .map(Into::into)
            .map_err(D::Error::custom)
    }
}

/// Abstract OpenPGP interface.
///
/// This is the old abstraction for drivers.  We now only have only
/// one driver, SOP, and in the future, all tests should directly use
/// the SOP interface.
///
/// In the mean time, we provide a method `sop()` that returns the SOP
/// interface.
pub trait OpenPGP: std::fmt::Debug {
    fn sop(&self) -> &Sop;
    fn version(&self) -> Result<Version>;
    fn encrypt(&self, recipient: &[u8], plaintext: &[u8]) -> Result<Data>;
    fn decrypt(&self, recipient: &[u8], ciphertext: &[u8]) -> Result<Data>;
    fn sign_detached(&self, _signer: &[u8], _data: &[u8]) -> Result<Data> {
        Err(Error::NotImplemented.into())
    }
    fn verify_detached(&self, _signer: &[u8], _data: &[u8], _sig: &[u8])
                       -> Result<Data>
    {
        Err(Error::NotImplemented.into())
    }
    fn generate_key(&self, _userids: &[&str]) -> Result<Data> {
        Err(Error::NotImplemented.into())
    }
}

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

    fn implementations(&self) -> Result<Vec<crate::Sop>> {
        let mut r: Vec<crate::Sop> = Vec::new();
        for d in self.drivers.iter() {
            r.push(sop::Sop::new(&d.path, &d.env)
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
        let c: Config =
            serde_json::from_reader(
                fs::File::open(cli.config).context("Opening config file")?
            ).context("Reading config file")?;
        c.set_rlimits().context("Setting resource limits")?;
        let implementations = c.implementations()
            .context("Setting up implementations")?;

        eprintln!("Configured engines:");
        for i in implementations.iter() {
            eprintln!("  - {}",
                      i.version().context(format!("Could not run {:?}", i))?);
        }

        let mut plan = plan::TestPlan::new(&c);
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

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Not implemented by the driver.
    #[error("This is not implemented by the driver.")]
    NotImplemented,

    /// This should not happen.
    #[error("This should not happen.")]
    InternalDriverError,

    /// Unspecified engine error.
    #[error("{}\nstdout:\n~~~snip~~~\n{}~~~snip~~~\nstderr:\n~~~snip~~~\n{}~~~snip~~~\n",
           _0, _1, _2)]
    EngineError(#[source] sop::SOPError, String, String),
}
