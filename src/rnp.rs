use std::path::{Path, PathBuf};
use std::process;
use std::io::Write;
use tempfile::{TempDir, NamedTempFile};

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use crate::{Implementation, Version, Error, Result};

const KEEP_HOMEDIRS: bool = false;

pub struct RNP {
    prefix: PathBuf,
    #[allow(dead_code)]
    homedir: TempDir,
}

impl RNP {
    pub fn new<P: AsRef<Path>>(prefix: P) -> Result<RNP> {
        let homedir = TempDir::new()?;
        Ok(RNP {
            prefix: prefix.as_ref().into(),
            homedir,
        })
    }

    fn run<I, S>(&self, args: I) -> Result<process::Output>
        where I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr>
    {
        let o = process::Command::new(self.prefix.join("rnp"))
            .arg("--homedir").arg(self.homedir.path())
            .args(args)
            .output()?;
        if o.status.success() {
            Ok(o)
        } else {
            Err(Error::EngineError(
                o.status, String::from_utf8_lossy(&o.stderr).to_string())
                .into())
        }
    }

    fn stash<S: Serialize>(&self, o: &S) -> Result<NamedTempFile> {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        o.serialize(&mut f)?;
        Ok(f)
    }

    fn stash_bytes<B: AsRef<[u8]>>(&self, o: B) -> Result<NamedTempFile> {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        f.write_all(o.as_ref())?;
        Ok(f)
    }

    fn import_certificate(&mut self, c: &openpgp::TPK) -> Result<()> {
        let cert = self.stash(&c.as_tsk())?;
        let o = process::Command::new(self.prefix.join("rnpkeys"))
            .arg("--homedir").arg(self.homedir.path())
            .arg("--import-key").arg(cert.path())
            .output()?;
        if o.status.success() {
            Ok(())
        } else {
            Err(Error::EngineError(
                o.status, String::from_utf8_lossy(&o.stderr).to_string())
                .into())
        }
    }
}

impl Drop for RNP {
    fn drop(&mut self) {
        if KEEP_HOMEDIRS {
            let homedir =
                std::mem::replace(&mut self.homedir, TempDir::new().unwrap());
            eprintln!("Leaving RNP homedir {:?} for inspection",
                      homedir.into_path());
        }
    }
}

impl crate::OpenPGP for RNP {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.prefix)
            .map(|i| -> Box<dyn crate::OpenPGP> { Box::new(i) })
    }

    fn version(&self) -> Result<crate::Version> {
        let o = self.run(&["--version"])?;
        let stderr = String::from_utf8_lossy(&o.stderr);
        let version = (
            &stderr[4..stderr.find("\n").unwrap_or(stderr.len())-1])
            .to_string();
        Ok(Version {
            implementation: Implementation::RNP,
            version,
        })
    }

    fn encrypt(&mut self, recipient: &openpgp::TPK, plaintext: &[u8])
               -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let plaintext_file = self.stash_bytes(plaintext)?;
        let o = self.run(&["--encrypt",
                           "--recipient",
                           &recipient.fingerprint().to_string(),
                           "--armor",
                           "--output=-",
                           plaintext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &openpgp::TPK, ciphertext: &[u8])
               -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let ciphertext_file = self.stash_bytes(ciphertext)?;
        let o = self.run(&["--decrypt",
                           "--output=-",
                           ciphertext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }
}
