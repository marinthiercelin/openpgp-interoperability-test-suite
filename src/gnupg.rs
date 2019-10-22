use std::path::{Path, PathBuf};
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use gpgme::{Context, EncryptFlags, Protocol};

use crate::{Implementation, Version, Result};

const KEEP_HOMEDIRS: bool = false;

pub struct GnuPG {
    engine: PathBuf,
    ctx: Context,
    #[allow(dead_code)]
    homedir: TempDir,
}

impl GnuPG {
    pub fn new<P: AsRef<Path>>(engine: P) -> Result<GnuPG> {
        let homedir = TempDir::new()?;
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
        ctx.set_armor(true);
        ctx.set_engine_path(
            String::from(engine.as_ref().to_string_lossy()))?;
        ctx.set_engine_home_dir(
            String::from(homedir.path().to_string_lossy()))?;
        Ok(GnuPG { engine: engine.as_ref().into(), ctx, homedir })
    }

    fn import_certificate(&mut self, c: &openpgp::TPK) -> Result<()> {
        let mut buf = Vec::new();
        c.as_tsk().serialize(&mut buf)?;
        self.ctx.import(buf)?;
        Ok(())
    }
}

impl Drop for GnuPG {
    fn drop(&mut self) {
        if KEEP_HOMEDIRS {
            let homedir =
                std::mem::replace(&mut self.homedir, TempDir::new().unwrap());
            eprintln!("Leaving GnuPG homedir {:?} for inspection",
                      homedir.into_path());
        }
    }
}

impl crate::OpenPGP for GnuPG {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.engine)
            .map(|i| -> Box<dyn crate::OpenPGP> { Box::new(i) })
    }

    fn version(&self) -> Result<crate::Version> {
        let version = self.ctx.engine_info();
        Ok(Version {
            implementation: Implementation::GnuPG,
            version: version.version().unwrap().into(),
        })
    }

    fn encrypt(&mut self, recipient: &openpgp::TPK, plaintext: &[u8])
               -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let key = self.ctx.get_key(recipient.fingerprint().to_string())?;
        let mut ciphertext = Vec::new();
        self.ctx.encrypt_with_flags(Some(&key), plaintext, &mut ciphertext,
                                    EncryptFlags::ALWAYS_TRUST)?;
        Ok(ciphertext.into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &openpgp::TPK, ciphertext: &[u8]) -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let mut plaintext = Vec::new();
        self.ctx.decrypt(ciphertext, &mut plaintext)?;
        Ok(plaintext.into_boxed_slice())
    }
}
