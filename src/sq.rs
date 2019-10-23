use std::process;
use std::io::Write;

use std::path::{Path, PathBuf};
use tempfile::{TempDir, NamedTempFile};

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use crate::{Data, Implementation, Version, Error, Result};

const KEEP_HOMEDIRS: bool = false;

pub struct Sq {
    sq: PathBuf,
    #[allow(dead_code)]
    homedir: TempDir,
}

impl Sq {
    pub fn new<P: AsRef<Path>>(executable: P) -> Result<Sq> {
        let homedir = TempDir::new()?;
        Ok(Sq { sq: executable.as_ref().into(), homedir })
    }

    fn run<I, S>(&self, args: I) -> Result<process::Output>
        where I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr>
    {
        let o = process::Command::new(&self.sq)
            .current_dir(self.homedir.path())
            .arg("--home").arg(self.homedir.path())
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
}

impl Drop for Sq {
    fn drop(&mut self) {
        if KEEP_HOMEDIRS {
            let homedir =
                std::mem::replace(&mut self.homedir, TempDir::new().unwrap());
            eprintln!("Leaving Sequoia homedir {:?} for inspection",
                      homedir.into_path());
        }
    }
}

impl crate::OpenPGP for Sq {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.sq)
            .map(|i| -> Box<dyn crate::OpenPGP> { Box::new(i) })
    }

    fn version(&self) -> Result<crate::Version> {
        let o = self.run(&["--version"])?;
        let version = String::from_utf8_lossy(&o.stdout[3..o.stdout.len()-1])
            .to_string();
        Ok(Version {
            implementation: Implementation::Sequoia,
            version,
        })
    }

    fn encrypt(&mut self, recipient: &openpgp::TPK, plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_file = self.stash(recipient)?;
        let plaintext_file = self.stash_bytes(plaintext)?;
        let o = self.run(&["encrypt",
                           "--recipient-key-file",
                           recipient_file.path().to_str().unwrap(),
                           plaintext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &openpgp::TPK, ciphertext: &[u8]) -> Result<Box<[u8]>> {
        let recipient_file = self.stash(&recipient.as_tsk())?;
        let ciphertext_file = self.stash_bytes(ciphertext)?;
        let o = self.run(&["decrypt",
                           "--secret-key-file",
                           recipient_file.path().to_str().unwrap(),
                           ciphertext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        let mut args = vec!["key", "generate", "--export", "key"];
        for u in userids {
            args.push("--userid");
            args.push(u);
        }
        self.run(&args[..])?;
        Ok(std::fs::read(self.homedir.path().join("key"))?.into_boxed_slice())
    }
}
