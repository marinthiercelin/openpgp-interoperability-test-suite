use std::fmt;
use std::fs;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
};

mod data;
mod tests;
mod templates;

mod sop;
pub use sop::Sop;

/// Maximum size of artifacts included in the results.
pub const MAXIMUM_ARTIFACT_SIZE: usize = 50_000;

/// Backends supported by the test suite.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct Version {
    pub implementation: Implementation,
    pub version: String,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.implementation, self.version)
    }
}

/// Chunks of data.
pub type Data = Box<[u8]>;

/// Abstract OpenPGP interface.
pub trait OpenPGP: std::fmt::Debug {
    fn new_context(&self) -> Result<Box<dyn OpenPGP>>;
    fn version(&self) -> Result<Version>;
    fn encrypt(&mut self, recipient: &[u8], plaintext: &[u8]) -> Result<Data>;
    fn decrypt(&mut self, recipient: &[u8], ciphertext: &[u8]) -> Result<Data>;
    fn sign_detached(&mut self, _signer: &[u8], _data: &[u8]) -> Result<Data> {
        Err(Error::NotImplemented.into())
    }
    fn verify_detached(&mut self, _signer: &[u8], _data: &[u8], _sig: &[u8])
                       -> Result<Data>
    {
        Err(Error::NotImplemented.into())
    }
    fn generate_key(&mut self, _userids: &[&str]) -> Result<Data> {
        Err(Error::NotImplemented.into())
    }
}

/// Test suite configuration.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    drivers: Vec<Driver>,
    #[serde(default)]
    rlimits: std::collections::HashMap<String, u64>,
}

/// A driver configuration.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Driver {
    driver: String,
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

    fn implementations(&self) -> Result<Vec<Box<dyn OpenPGP + Sync>>> {
        let mut r: Vec<Box<dyn OpenPGP + Sync>> = Vec::new();
        for d in self.drivers.iter() {
            r.push(match d.driver.as_str() {
                "sop" => Box::new(sop::Sop::new(&d.path, &d.env)
                                 .context("Creating sop backend")?),
                _ => return Err(anyhow::anyhow!("Unknown driver {:?}",
                                                     d.driver)),
            });
        }
        Ok(r)
    }
}

fn main() -> anyhow::Result<()> {
    let c: Config =
        serde_json::from_reader(
            fs::File::open("config.json").context("Opening config file")?
        ).context("Reading config file")?;
    c.set_rlimits().context("Setting resource limits")?;
    let implementations = c.implementations()
        .context("Setting up implementations")?;

    eprintln!("Configured engines:");
    for i in implementations.iter() {
        eprintln!("  - {}",
                  i.version().context(format!("Could not run {:?}", i))?);
    }

    let mut report = templates::Report::new(&c);
    tests::schedule(&mut report)?;

    use templates::Renderable;
    println!("{}", report.run(&implementations[..])?.render()?);
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
