use std::fmt;
use std::fs;

use failure::ResultExt;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
};

mod data;
mod tests;
mod templates;

mod sq;
mod gnupg;
mod rnp;
mod dkgpg;
mod sop;

/// Backends supported by the test suite.
#[derive(Debug, Clone)]
pub enum Implementation {
    Sequoia,
    GnuPG,
    RNP,
    DKGPG,
    Sop(String),
}

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Implementation::Sop(s) => f.write_str(&s),
            _ => write!(f, "{:?}", self),
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
pub trait OpenPGP {
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
    fn implementations(&self) -> Result<Vec<Box<dyn OpenPGP + Sync>>> {
        let mut r: Vec<Box<dyn OpenPGP + Sync>> = Vec::new();
        for d in self.drivers.iter() {
            r.push(match d.driver.as_str() {
                "sq" => Box::new(sq::Sq::new(&d.path)?),
                "gnupg" => Box::new(gnupg::GnuPG::new(&d.path)?),
                "rnp" => Box::new(rnp::RNP::new(&d.path)?),
                "dkgpg" => Box::new(dkgpg::DKGPG::new(&d.path)?),
                "sop" => Box::new(sop::Sop::new(&d.path, &d.env)?),
                _ => return Err(failure::format_err!("Unknown driver {:?}",
                                                     d.driver)),
            });
        }
        Ok(r)
    }
}

fn real_main() -> failure::Fallible<()> {
    let c: Config =
        serde_json::from_reader(
            fs::File::open("config.json").context("Opening config file")?
        ).context("Reading config file")?;
    let implementations = c.implementations()
        .context("Reading config file")?;

    eprintln!("Configured engines:");
    for i in implementations.iter() {
        eprintln!("  - {}", i.version()?);
    }

    let mut report = templates::Report::new(&c);
    tests::schedule(&mut report)?;

    use templates::Renderable;
    println!("{}", report.run(&implementations[..])?.render()?);
    Ok(())
}

fn main() {
    if let Err(e) = real_main() {
        let mut cause = e.as_fail();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        std::process::exit(2);
    }
}

#[derive(failure::Fail, Debug, Clone)]
pub enum Error {
    /// Not implemented by the driver.
    #[fail(display = "This is not implemented by the driver.")]
    NotImplemented,

    /// This should not happen.
    #[fail(display = "This should not happen.")]
    InternalDriverError,

    /// Unspecified engine error.
    #[fail(display = "Unspecified engine error.  Status: {}, stderr:\n{}",
           _0, _1)]
    EngineError(std::process::ExitStatus, String),
}
