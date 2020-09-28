use std::collections::HashMap;
use std::process;
use std::io::Write;

use std::path::{Path, PathBuf};
use tempfile::{TempDir, NamedTempFile};

use crate::{Data, Implementation, Version, Error, Result};

const KEEP_HOMEDIRS: bool = false;

#[derive(Debug)]
pub struct Sop {
    sop: PathBuf,
    env: HashMap<String, String>,
    homedir: TempDir,
}

impl Sop {
    pub fn new<P: AsRef<Path>>(executable: P,
                               env: &HashMap<String, String>)
                               -> Result<Sop> {
        let homedir = TempDir::new()?;
        Ok(Sop {
            sop: executable.as_ref().into(),
            env: env.clone(),
            homedir,
        })
    }

    fn run<D, I, S>(&self, args: I, input: D) -> Result<process::Output>
        where D: AsRef<[u8]>,
              I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr>
    {
        let mut child = process::Command::new(&self.sop)
            .envs(&self.env)
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
                o.status,
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string())
                .into())
        }
    }

    fn stash_bytes<B: AsRef<[u8]>>(&self, o: B) -> Result<NamedTempFile> {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        f.write_all(o.as_ref())?;
        Ok(f)
    }
}

impl Drop for Sop {
    fn drop(&mut self) {
        if KEEP_HOMEDIRS {
            let homedir =
                std::mem::replace(&mut self.homedir, TempDir::new().unwrap());
            eprintln!("Leaving sop homedir {:?} for inspection",
                      homedir.into_path());
        }
    }
}

impl crate::OpenPGP for Sop {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.sop, &self.env)
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
            implementation: Implementation::Sop(name),
            version,
        })
    }

    fn encrypt(&mut self, recipient: &[u8], plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_file = self.stash_bytes(recipient)?;
        let o = self.run(&["encrypt",
                           recipient_file.path().to_str().unwrap()],
                           plaintext)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &[u8], ciphertext: &[u8]) -> Result<Box<[u8]>> {
        let recipient_file = self.stash_bytes(recipient)?;
        let o = self.run(&["decrypt",
                           recipient_file.path().to_str().unwrap()],
                           ciphertext)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn sign_detached(&mut self, signer: &[u8], data: &[u8])
                     -> Result<Data> {
        let signer_file = self.stash_bytes(signer)?;
        let o = self.run(&["sign",
                           signer_file.path().to_str().unwrap()],
                         data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn verify_detached(&mut self, signer: &[u8], data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        let signer_file = self.stash_bytes(signer)?;
        let sig_file = self.stash_bytes(sig)?;
        let o = self.run(&["verify",
                           sig_file.path().to_str().unwrap(),
                           signer_file.path().to_str().unwrap()],
                         data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        let mut args = vec!["generate-key"];
        for u in userids {
            args.push(u);
        }
        let o = self.run(&args[..], &[])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }
}
