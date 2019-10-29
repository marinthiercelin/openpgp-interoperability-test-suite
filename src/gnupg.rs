use std::path::{Path, PathBuf};
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use gpgme::{Context, EncryptFlags, Protocol};

use crate::{Data, Implementation, Version, Result};

const KEEP_HOMEDIRS: bool = false;

pub struct GnuPG {
    engine: PathBuf,
    homedir: TempDir,
}

impl GnuPG {
    pub fn new<P: AsRef<Path>>(engine: P) -> Result<GnuPG> {
        let homedir = TempDir::new()?;
        //std::fs::write(homedir.path().join("gpg.conf"),
        //               "batch\n\
        //                ")?;
        // XXX
        Ok(GnuPG {
            engine: engine.as_ref().into(),
            homedir,
        })
    }

    fn ctx(&self) -> Result<Context> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
        ctx.set_armor(true);
        ctx.set_engine_path(
            String::from(self.engine.to_str().unwrap()))?;
        ctx.set_engine_home_dir(
            String::from(self.homedir.path().to_string_lossy()))?;
        Ok(ctx)
    }

    fn import_certificate(&mut self, c: &openpgp::TPK) -> Result<()> {
        let mut buf = Vec::new();
        c.as_tsk().serialize(&mut buf)?;
        self.ctx()?.import(buf)?;
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
        Ok(Version {
            implementation: Implementation::GnuPG,
            version: self.ctx()?.engine_info().version().unwrap().into(),
        })
    }

    fn encrypt(&mut self, recipient: &openpgp::TPK, plaintext: &[u8])
               -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let key = self.ctx()?.get_key(recipient.fingerprint().to_string())?;
        let mut ciphertext = Vec::new();
        self.ctx()?.encrypt_with_flags(Some(&key), plaintext, &mut ciphertext,
                                    EncryptFlags::ALWAYS_TRUST)?;
        Ok(ciphertext.into_boxed_slice())
    }

    fn decrypt(&mut self, recipient: &openpgp::TPK, ciphertext: &[u8]) -> Result<Box<[u8]>> {
        self.import_certificate(recipient)?;
        let mut plaintext = Vec::new();
        self.ctx()?.decrypt(ciphertext, &mut plaintext)?;
        Ok(plaintext.into_boxed_slice())
    }

    fn sign_detached(&mut self, signer: &openpgp::TPK, data: &[u8])
                     -> Result<Data> {
        self.import_certificate(signer)?;
        let mut sig = Vec::new();
        self.ctx()?.sign(gpgme::SignMode::Detached, data, &mut sig)?;
        Ok(sig.into_boxed_slice())
    }

    fn verify_detached(&mut self, signer: &openpgp::TPK, data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        self.import_certificate(signer)?;
        let sigs = self.ctx()?.verify_detached(sig, data)?;
        Ok(format!("{:?}", sigs.signatures()).into_bytes().into_boxed_slice())
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        if userids.len() == 0 {
            return Err(failure::format_err!(
                "Generating UID-less keys not supported"));
        }

        use gpgme::CreateKeyFlags;
        let r = self.ctx()?.create_key_with_flags(userids[0], "default", None,
                                               CreateKeyFlags::NOPASSWD)?;
        let fp = r.fingerprint().unwrap();
        let key = self.ctx()?.get_key(fp)?;
        for &u in &userids[1..] {
            self.ctx()?.add_uid(&key, u)?;
        }
        let mut r = Vec::new();
        self.ctx()?.export_keys(&[key], gpgme::ExportMode::SECRET, &mut r)?;
        Ok(r.into_boxed_slice())
    }
}
