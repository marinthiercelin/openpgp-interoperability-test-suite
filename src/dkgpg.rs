use std::path::{Path, PathBuf};
use std::process;
use std::io::Write;
use tempfile::{TempDir, NamedTempFile};

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

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

    // XXX: Workaround, see:
    // https://savannah.nongnu.org/bugs/index.php?57098
    fn stash_armored<B: AsRef<[u8]>>(&self, o: B, kind: openpgp::armor::Kind)
                                     -> Result<NamedTempFile>
    {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        if o.as_ref().get(0) == Some(&('-' as u8)) {
            // Already armored.
            f.write_all(o.as_ref())?;
        } else {
            let mut sink = openpgp::armor::Writer::new(&mut f, kind, &[])?;
            sink.write_all(o.as_ref())?;
            sink.finalize()?;
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

    fn encrypt(&mut self, recipient: &[u8], plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_fp = openpgp::Cert::from_bytes(recipient)?.fingerprint();
        let recipient_file = self.stash_bytes(recipient)?;
        let plaintext_file = self.stash_bytes(plaintext)?;
        let o = self.run("dkg-encrypt",
                         &["-k",
                           recipient_file.path().to_str().unwrap(),
                           "-r",
                           &format!("{:X}", recipient_fp),
                           "-i",
                           plaintext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &[u8], ciphertext: &[u8])
               -> Result<Box<[u8]>> {
        // XXX: Workaround, see:
        // https://savannah.nongnu.org/bugs/index.php?57098
        let recipient_file =
            self.stash_armored(recipient, openpgp::armor::Kind::SecretKey)?;
        let ciphertext_file = self.stash_bytes(ciphertext)?;
        let o = self.run("dkg-decrypt",
                         &["-y",
                           recipient_file.path().to_str().unwrap(),
                           "-i",
                           ciphertext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn sign_detached(&mut self, signer: &[u8], data: &[u8])
                     -> Result<Data> {
        // XXX: Workaround, see:
        // https://savannah.nongnu.org/bugs/index.php?57098
        let signer_file =
            self.stash_armored(signer,
                               openpgp::armor::Kind::SecretKey)?;
        let data_file = self.stash_bytes(data)?;
        let o = self.run("dkg-sign",
                         &["-y",
                           signer_file.path().to_str().unwrap(),
                           "-i",
                           data_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn verify_detached(&mut self, signer: &[u8], data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        let signer_file = self.stash_bytes(signer)?;
        let data_file = self.stash_bytes(data)?;
        let sig_file =
            self.stash_armored(sig, openpgp::armor::Kind::Signature)?;
        let o = self.run("dkg-verify",
                         &["-i",
                           data_file.path().to_str().unwrap(),
                           "-s",
                           sig_file.path().to_str().unwrap(),
                           "-k",
                           signer_file.path().to_str().unwrap()])?;
        Ok(o.stderr.clone().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        if userids.len() == 0 {
            return Err(anyhow::anyhow!(
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
