use std::path::{Path, PathBuf};
use std::process;
use std::io::Write;
use tempfile::{TempDir, NamedTempFile};

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{Data, Implementation, Version, Error, Result};

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

    fn run<I, S>(&self, tool: &str, args: I) -> Result<process::Output>
        where I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr>
    {
        let o = process::Command::new(self.prefix.join(tool))
            .arg("--homedir").arg(self.homedir.path())
            .args(args)
            .output()?;
        if o.status.success() {
            Ok(o)
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

    fn import_certificate(&mut self, c: &[u8]) -> Result<()> {
        let cert = self.stash_bytes(c)?;
        self.run("rnpkeys",
                 &["--import-key", cert.path().to_str().unwrap()])?;
        Ok(())
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
        let o = self.run("rnp", &["--version"])?;
        let stderr = String::from_utf8_lossy(&o.stderr);
        let version = (
            &stderr[4..stderr.find("\n").unwrap_or(stderr.len())-1])
            .to_string();
        Ok(Version {
            implementation: Implementation::RNP,
            version,
        })
    }

    fn encrypt(&mut self, recipient: &[u8], plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_fp = openpgp::Cert::from_bytes(recipient)?.fingerprint();
        self.import_certificate(recipient)?;
        let plaintext_file = self.stash_bytes(plaintext)?;
        let o = self.run("rnp",
                         &["--encrypt",
                           "--recipient",
                           &format!("{:X}", recipient_fp),
                           "--armor",
                           "--output=-",
                           plaintext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &[u8], ciphertext: &[u8])
               -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let ciphertext_file = self.stash_bytes(ciphertext)?;
        let o = self.run("rnp",
                         &["--decrypt",
                           "--output=-",
                           ciphertext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn sign_detached(&mut self, signer: &[u8], data: &[u8])
                     -> Result<Data> {
        self.import_certificate(signer)?;
        let data_file = self.stash_bytes(data)?;
        let o = self.run("rnp",
                         &["--sign", "--detached",
                           "--output=-", "--armor",
                           data_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn verify_detached(&mut self, signer: &[u8], data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        self.import_certificate(signer)?;
        let data_file = self.stash_bytes(data)?;
        let sig_file_name =
            format!("{}.sig", data_file.path().to_str().unwrap());
        std::fs::write(&sig_file_name, sig)?;
        let o = self.run("rnp",
                         &["--verify", &sig_file_name])?;
        Ok(o.stderr.clone().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        if true {
            return Err(anyhow::anyhow!(
                "rnpkeys cannot create unprotected keys"));
        }

        if userids.len() == 0 {
            return Err(anyhow::anyhow!(
                "Generating UID-less keys not supported"));
        }

        let mut args = vec!["--generate-key"];
        for u in userids {
            args.push("--userid");
            args.push(u);
        }

        self.run("rnpkeys", &args[..])?;
        Ok(std::fs::read(self.homedir.path().join("secring.gpg"))?
           .into_boxed_slice())
    }
}
