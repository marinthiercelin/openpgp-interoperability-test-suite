use std::cmp::Ordering;
use std::process;
use std::str::FromStr;
use std::io::Write;

use std::path::{Path, PathBuf};
use tempfile::{TempDir, NamedTempFile};

use crate::{Data, Implementation, Version, Error, Result};

const KEEP_HOMEDIRS: bool = false;

#[derive(Debug, PartialEq, Eq)]
struct SqVersion {
    major: usize,
    minor: usize,
    patch: usize,
    pre_release: Option<String>,
}

impl Ord for SqVersion {
    fn cmp(&self, other: &SqVersion) -> Ordering {
        self.major.cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.pre_release.cmp(&other.pre_release))
    }
}

impl PartialOrd for SqVersion {
    fn partial_cmp(&self, other: &SqVersion) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for SqVersion {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut v_pre = s.split("-");
        let mut v =
            v_pre.next().ok_or(failure::err_msg("No version string found"))?
            .split(".");
        Ok(Self {
            major: v.next().unwrap().parse()?,
            minor: v.next().unwrap().parse()?,
            patch: v.next().unwrap().parse()?,
            pre_release: v_pre.next().map(|p| p.into()),
        })
    }
}

impl SqVersion {
    fn detect(p: &Path) -> Result<Self> {
        let o = process::Command::new(p)
            .arg("--version")
            .output()?;
        std::str::from_utf8(&o.stdout)?.trim()
            .split(' ').nth(1).unwrap()
            .parse()
    }
}

pub struct Sq {
    sq: PathBuf,
    #[allow(dead_code)]
    homedir: TempDir,
    version: SqVersion,
}

impl Sq {
    pub fn new<P: AsRef<Path>>(executable: P) -> Result<Sq> {
        let homedir = TempDir::new()?;
        let version = SqVersion::detect(executable.as_ref())?;
        Ok(Sq { sq: executable.as_ref().into(), homedir, version })
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

    fn encrypt(&mut self, recipient: &[u8], plaintext: &[u8])
               -> Result<Box<[u8]>> {
        let recipient_file = self.stash_bytes(recipient)?;
        let plaintext_file = self.stash_bytes(plaintext)?;
        let o = self.run(&["encrypt",
                           "--recipient-key-file",
                           recipient_file.path().to_str().unwrap(),
                           plaintext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &[u8], ciphertext: &[u8]) -> Result<Box<[u8]>> {
        let recipient_file = self.stash_bytes(recipient)?;
        let ciphertext_file = self.stash_bytes(ciphertext)?;
        let o = self.run(&["decrypt",
                           "--secret-key-file",
                           recipient_file.path().to_str().unwrap(),
                           ciphertext_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn sign_detached(&mut self, signer: &[u8], data: &[u8])
                     -> Result<Data> {
        let signer_file = self.stash_bytes(signer)?;
        let data_file = self.stash_bytes(data)?;
        let o = self.run(&["sign", "--detached",
                           "--secret-key-file",
                           signer_file.path().to_str().unwrap(),
                           data_file.path().to_str().unwrap()])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    fn verify_detached(&mut self, signer: &[u8], data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        let signer_file = self.stash_bytes(signer)?;
        let data_file = self.stash_bytes(data)?;
        let sig_file = self.stash_bytes(sig)?;
        let o = self.run(&["verify",
                           "--detached",
                           sig_file.path().to_str().unwrap(),
                           if self.version < "0.13.0".parse().unwrap() {
                               "--public-key-file"
                           } else {
                               "--sender-cert-file"
                           },
                           signer_file.path().to_str().unwrap(),
                           data_file.path().to_str().unwrap()])?;
        Ok(o.stderr.clone().into_boxed_slice())
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
