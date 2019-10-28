use std::path::{Path, PathBuf};
use std::process;
use std::io::Write;
use tempfile::{TempDir, NamedTempFile};

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use crate::{Data, Implementation, Version, Error, Result};

const KEEP_HOMEDIRS: bool = false;

pub struct DKGPG {
    prefix: PathBuf,
    #[allow(dead_code)]
    homedir: TempDir,
}

impl DKGPG {
    pub fn new<P: AsRef<Path>>(prefix: P) -> Result<DKGPG> {
        let homedir = TempDir::new()?;
        Ok(DKGPG {
            prefix: prefix.as_ref().into(),
            homedir,
        })
    }

    fn run<I, S>(&self, tool: &str, args: I) -> Result<process::Output>
        where I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr>
    {
        let o = process::Command::new(&self.prefix.join(tool))
            .current_dir(self.homedir.path())
            .arg("--verbose")
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

    // XXX: Workaround, see:
    // https://savannah.nongnu.org/bugs/index.php?57098
    fn stash_armored<S: Serialize>(&self, o: &S, kind: openpgp::armor::Kind)
                                   -> Result<NamedTempFile>
    {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        {
            let mut sink = openpgp::armor::Writer::new(&mut f, kind, &[])?;
            o.serialize(&mut sink)?;
        }
        Ok(f)
    }

    fn stash_bytes<B: AsRef<[u8]>>(&self, o: B) -> Result<NamedTempFile> {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        f.write_all(o.as_ref())?;
        Ok(f)
    }
}

impl Drop for DKGPG {
    fn drop(&mut self) {
        if KEEP_HOMEDIRS {
            let homedir =
                std::mem::replace(&mut self.homedir, TempDir::new().unwrap());
            eprintln!("Leaving DKGPG homedir {:?} for inspection",
                      homedir.into_path());
        }
    }
}

impl crate::OpenPGP for DKGPG {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.prefix)
            .map(|i| -> Box<dyn crate::OpenPGP> { Box::new(i) })
    }

    fn version(&self) -> Result<crate::Version> {
        let o = self.run("dkg-encrypt", &["--version"])?;
        let stdout = String::from_utf8_lossy(&o.stdout);
        let version = stdout.split(' ').nth(1).unwrap_or("unknown").to_string();
        Ok(Version {
            implementation: Implementation::DKGPG,
            version,
        })
    }

    fn encrypt(&mut self, recipient: &openpgp::TPK, plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_file = self.stash(recipient)?;
        let plaintext_file = self.stash_bytes(plaintext)?;
        let o = self.run("dkg-encrypt",
                         &["-k",
                           recipient_file.path().to_str().unwrap(),
                           "-r",
                           &recipient.fingerprint().to_hex(),
                           "-i",
                           plaintext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &openpgp::TPK, ciphertext: &[u8])
               -> Result<Box<[u8]>> {
        // XXX: Workaround, see:
        // https://savannah.nongnu.org/bugs/index.php?57098
        let recipient_file =
            self.stash_armored(&recipient.as_tsk(), openpgp::armor::Kind::SecretKey)?;
        let ciphertext_file = self.stash_bytes(ciphertext)?;
        let o = self.run("dkg-decrypt",
                         &["-y",
                           recipient_file.path().to_str().unwrap(),
                           "-i",
                           ciphertext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        if userids.len() == 0 {
            return Err(failure::format_err!(
                "Generating UID-less keys not supported"));
        }

        let mut args = vec!["--no-passphrase", "--yaot"];
        for u in userids {
            args.push("-u");
            args.push(u);
        }
        args.push("localhost");
        self.run("dkg-generate", &args[..])?;
        Ok(std::fs::read(self.homedir.path().join("localhost-sec.asc"))?
           .into_boxed_slice())
    }
}
