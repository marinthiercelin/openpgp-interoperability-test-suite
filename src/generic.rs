use std::process;
use std::io::Write;

use std::path::{Path, PathBuf};
use tempfile::{TempDir, NamedTempFile};

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use crate::{Data, Implementation, Version, Error, Result};

const KEEP_HOMEDIRS: bool = false;

pub struct Generic {
    generic: PathBuf,
    #[allow(dead_code)]
    homedir: TempDir,
}

impl Generic {
    pub fn new<P: AsRef<Path>>(executable: P) -> Result<Generic> {
        let homedir = TempDir::new()?;
        Ok(Generic { generic: executable.as_ref().into(), homedir })
    }

    fn run<D, I, S>(&self, args: I, input: D) -> Result<process::Output>
        where D: AsRef<[u8]>,
              I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr>
    {
        let mut child = process::Command::new(&self.generic)
            .args(args)
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped())
            .stderr(process::Stdio::piped())
            .spawn()?;
        child.stdin.as_mut().unwrap().write_all(input.as_ref())?;
        let o = child.wait_with_output()?;
        if o.status.success() {
            Ok(o)
        } else if let Some(69) = o.status.code() {
            Err(Error::NotImplemented.into())
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

impl Drop for Generic {
    fn drop(&mut self) {
        if KEEP_HOMEDIRS {
            let homedir =
                std::mem::replace(&mut self.homedir, TempDir::new().unwrap());
            eprintln!("Leaving generic homedir {:?} for inspection",
                      homedir.into_path());
        }
    }
}

impl crate::OpenPGP for Generic {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.generic)
            .map(|i| -> Box<dyn crate::OpenPGP> { Box::new(i) })
    }

    fn version(&self) -> Result<crate::Version> {
        let o = self.run(&["version"], &[])?;
        let stdout = String::from_utf8_lossy(&o.stdout);
        let name =
            stdout.trim().split(' ').nth(0).unwrap_or("unknown").to_string();
        let version =
            stdout.trim().split(' ').nth(1).unwrap_or("unknown").to_string();
        Ok(Version {
            implementation: Implementation::Generic(name),
            version,
        })
    }

    fn encrypt(&mut self, recipient: &openpgp::TPK, plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_file = self.stash(recipient)?;
        let o = self.run(&["encrypt",
                           recipient_file.path().to_str().unwrap()],
                           plaintext)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &openpgp::TPK, ciphertext: &[u8]) -> Result<Box<[u8]>> {
        let recipient_file = self.stash(&recipient.as_tsk())?;
        let o = self.run(&["decrypt",
                           recipient_file.path().to_str().unwrap()],
                           ciphertext)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn sign_detached(&mut self, signer: &openpgp::TPK, data: &[u8])
                     -> Result<Data> {
        let signer_file = self.stash(&signer.as_tsk())?;
        let o = self.run(&["sign",
                           signer_file.path().to_str().unwrap()],
                         data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn verify_detached(&mut self, signer: &openpgp::TPK, data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        let signer_file = self.stash(signer)?;
        let sig_file = self.stash_bytes(sig)?;
        let o = self.run(&["verify",
                           sig_file.path().to_str().unwrap(),
                           signer_file.path().to_str().unwrap()],
                         data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        let mut args = vec!["generate"];
        for u in userids {
            args.push(u);
        }
        let o = self.run(&args[..], &[])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }
}
