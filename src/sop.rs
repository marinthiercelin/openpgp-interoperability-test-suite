//! SOP interface for use in tests.
//!
//! This interface is used by the tests to drive the underlying SOP
//! implementations.  It exposes the [SOP interface] in a robust and
//! idiomatic way.  Every [subcommand] maps to a method on the [`Sop`]
//! object, which returns a builder to further customize the
//! operation.
//!
//! [SOP interface]: https://gitlab.com/dkg/openpgp-stateless-cli/-/blob/main/sop.md#introduction
//! [subcommand]: https://gitlab.com/dkg/openpgp-stateless-cli/-/blob/main/sop.md#subcommands
//!
//! # Examples
//!
//! This is roughly equivalent to the [SOP examples].
//!
//! [SOP examples]: https://gitlab.com/dkg/openpgp-stateless-cli/-/blob/main/sop.md#examples
//!
//! ```rust,ignore
//! fn sop_examples(sop: &Sop) -> Result<()> {
//!     let alice_sec = sop
//!         .generate_key()
//!         .userids(vec!["Alice Lovelace <alice@openpgp.example>"])?;
//!     let alice_pgp = sop
//!         .extract_cert()
//!         .key(&alice_sec)?;
//!
//!     let bob_sec = sop
//!         .generate_key()
//!         .userids(vec!["Bob Babbage <bob@openpgp.example>"])?;
//!     let bob_pgp = sop
//!         .extract_cert()
//!         .key(&bob_sec)?;
//!
//!     let statement = "Hello World :)";
//!     let statement_asc = sop
//!         .sign()
//!         .as_(SignAs::Text)
//!         .key(&alice_sec)
//!         .data(statement.as_bytes())?;
//!     let verifications = sop
//!         .verify()
//!         .cert(&alice_pgp)
//!         .signatures(&statement_asc)
//!         .data(statement.as_bytes()).unwrap();
//!     assert_eq!(verifications.len(), 1);
//!
//!     let ciphertext = sop
//!         .encrypt()
//!         .signer_key(&alice_sec)
//!         .as_(EncryptAs::MIME)
//!         .cert(&bob_pgp)
//!         .plaintext(statement.as_bytes()).unwrap();
//!     let plaintext = sop
//!         .decrypt()
//!         .key(&bob_sec)
//!         .ciphertext(&ciphertext).unwrap();
//!     assert_eq!(&plaintext.1[..], statement.as_bytes());
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::process::{self, ExitStatus};
use std::os::unix::process::ExitStatusExt;
use std::io::{self, Write};

use std::path::{Path, PathBuf};
use tempfile::{TempDir, NamedTempFile};
use chrono::{DateTime, offset::Utc};
use anyhow::Context;

use sequoia_openpgp as openpgp;

use crate::{Data, Result};

const KEEP_HOMEDIRS: bool = false;

/// SOP interface for use in tests.
#[derive(Debug)]
pub struct Sop {
    sop: PathBuf,
    version: Version,
    env: HashMap<String, String>,
    homedir: TempDir,
}

impl Sop {
    /// Gets version information.
    pub fn version(&self) -> Result<Version> {
        Ok(self.version.clone())
    }

    /// Generates a Secret Key.
    ///
    /// Customize the operation using the builder [`GenerateKey`].
    pub fn generate_key(&self) -> GenerateKey {
        GenerateKey {
            sop: self,
            no_armor: false,
        }
    }

    /// Extracts a Certificate from a Secret Key.
    ///
    /// Customize the operation using the builder [`ExtractCert`].
    pub fn extract_cert(&self) -> ExtractCert {
        ExtractCert {
            sop: self,
            no_armor: false,
        }
    }

    /// Creates Detached Signatures.
    ///
    /// Customize the operation using the builder [`Sign`].
    pub fn sign(&self) -> Sign {
        Sign {
            sop: self,
            no_armor: false,
            as_: Default::default(),
            keys: Default::default(),
        }
    }

    /// Verifies Detached Signatures.
    ///
    /// Customize the operation using the builder [`Verify`].
    pub fn verify(&self) -> Verify {
        Verify {
            sop: self,
            not_before: None,
            not_after: None,
            certs: Default::default(),
        }
    }

    /// Encrypts a Message.
    ///
    /// Customize the operation using the builder [`Encrypt`].
    pub fn encrypt(&self) -> Encrypt {
        Encrypt {
            sop: self,
            no_armor: false,
            as_: Default::default(),
            passwords: Default::default(),
            sign_with: Default::default(),
            certs: Default::default(),
        }
    }

    /// Decrypts a Message.
    ///
    /// Customize the operation using the builder [`Decrypt`].
    pub fn decrypt(&self) -> Decrypt {
        Decrypt {
            verify: self.verify(),
            session_key_out: Default::default(),
            session_keys: Default::default(),
            passwords: Default::default(),
            keys: Default::default(),
        }
    }

    /// Verifies Inline-Signed Messages.
    ///
    /// Customize the operation using the builder [`InlineVerify`].
    pub fn inline_verify(&self) -> InlineVerify {
        InlineVerify {
            sop: self,
            not_before: None,
            not_after: None,
            certs: Default::default(),
        }
    }

    /// Converts binary OpenPGP data to ASCII.
    ///
    /// Customize the operation using the builder [`Armor`].
    pub fn armor(&self) -> Armor {
        Armor {
            sop: self,
            label: Default::default(),
        }
    }

    /// Converts ASCII OpenPGP data to binary.
    ///
    /// Customize the operation using the builder [`Dearmor`].
    pub fn dearmor(&self) -> Dearmor {
        Dearmor {
            sop: self,
        }
    }
}

/// Internal functions.  Do not use in tests.
impl Sop {
    pub fn new<P: AsRef<Path>>(executable: P) -> Result<Sop> {
        Self::with_env(executable, Default::default())
    }

    pub fn with_env<P: AsRef<Path>>(executable: P,
                                    env: HashMap<String, String>)
                                    -> Result<Sop> {
        let homedir = TempDir::new()?;
        let mut sop = Sop {
            sop: executable.as_ref().into(),
            version: Default::default(),
            env,
            homedir,
        };
        sop.version = sop._version()?;
        Ok(sop)
    }

    /// Gets version information.
    fn _version(&self) -> Result<Version> {
        let o = self.run(&["version"], &[])?;
        let frontend = String::from_utf8_lossy(&o.stdout)
            .trim().to_string();

        let mut backend = self.run(&["version", "--backend"], &[])
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().into())
            .ok();

        // Did they just ignore the --backend?
        if backend.as_ref() == Some(&frontend) {
            backend = None;
        }

        let mut extended = self.run(&["version", "--extended"], &[])
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().into())
            .ok();

        // Did they just ignore the --extended?
        if extended.as_ref() == Some(&frontend) {
            extended = None;
        }

        let summary = if let Some(b) = &backend {
            format!("{} ({})", b, frontend)
        } else {
            frontend.clone()
        };

        Ok(Version {
            frontend,
            backend,
            extended,
            summary,
        })
    }

    fn run<D, I, S>(&self, args: I, input: D)
                    -> std::result::Result<process::Output, ErrorWithOutput>
        where D: AsRef<[u8]>,
              I: IntoIterator<Item=S>, S: AsRef<std::ffi::OsStr> + fmt::Debug
    {
        let args = args.into_iter().collect::<Vec<_>>();
        let mut child = process::Command::new(&self.sop)
            .envs(&self.env)
            .args(args)
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped())
            .stderr(process::Stdio::piped())
            .spawn()?;
        let write_result =
            child.stdin.as_mut().unwrap().write_all(input.as_ref());
        let o = child.wait_with_output()?;

        if let Err(e) = write_result {
            Err(ErrorWithOutput::new(e, o))
        } else if o.status.success() {
            Ok(o)
        } else {
            Err(ErrorWithOutput::new(o.status, o))
        }
    }

    /// Writes the given data to a temporary file.
    ///
    /// Returns the path to the temporary file.  The temporary file is
    /// pushed into `tmp`, and will be deleted once `tmp` is dropped.
    fn stash_bytes<B: AsRef<[u8]>>(&self, o: B,
                                   temporaries: &mut Vec<NamedTempFile>)
                                   -> Result<String> {
        let mut f = NamedTempFile::new_in(self.homedir.path())?;
        f.write_all(o.as_ref())?;
        let p = f.path().to_str().unwrap().to_string();
        temporaries.push(f);
        Ok(p)
    }

    /// Allocates a path to write results into.
    ///
    /// Returns the allocated path.  No file at path will be created.
    /// If you create this file, you need to also remove it later.
    ///
    /// A temporary file is pushed into `tmp`, and will be deleted
    /// once `tmp` is dropped.  This temporary file is a stand-in for
    /// the allocated path.
    fn allocate_out_file(&self, temporaries: &mut Vec<NamedTempFile>)
                         -> Result<String> {
        let f = NamedTempFile::new_in(self.homedir.path())?;
        let p = format!("{}.out", f.path().to_str().unwrap());
        temporaries.push(f);
        Ok(p)
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

/// Builder for [`Sop::generate_key`].
pub struct GenerateKey<'s> {
    sop: &'s Sop,
    no_armor: bool,
}

impl GenerateKey<'_> {
    /// Disables armor encoding.
    pub fn no_armor(mut self) -> Self {
        self.no_armor = true;
        self
    }

    /// Generates a Secret Key.
    pub fn userids<'u>(self, userids: impl IntoIterator<Item = &'u str>)
                   -> Result<Data> {
        let mut args = vec!["generate-key"];
        if self.no_armor {
            args.push("--no-armor");
        }
        for u in userids {
            args.push(u);
        }
        let o = self.sop.run(&args[..], &[])?;
        Ok(o.stdout.into())
    }
}

/// Builder for [`Sop::extract_cert`].
pub struct ExtractCert<'s> {
    sop: &'s Sop,
    no_armor: bool,
}

impl ExtractCert<'_> {
    /// Disables armor encoding.
    pub fn no_armor(mut self) -> Self {
        self.no_armor = true;
        self
    }

    /// Extracts the cert from `key`.
    pub fn key(self, key: &[u8]) -> Result<Data> {
        let mut args = vec!["extract-cert"];
        if self.no_armor {
            args.push("--no-armor");
        }
        let o = self.sop.run(&args[..], key)?;
        Ok(o.stdout.into())
    }
}

/// Builder for [`Sop::sign`].
pub struct Sign<'s> {
    sop: &'s Sop,
    no_armor: bool,
    as_: SignAs,
    keys: Vec<&'s [u8]>,
}

impl<'s> Sign<'s> {
    /// Disables armor encoding.
    pub fn no_armor(mut self) -> Self {
        self.no_armor = true;
        self
    }

    /// Sets signature mode.
    pub fn as_(mut self, as_: SignAs) -> Self {
        self.as_ = as_;
        self
    }

    /// Adds the signer key.
    pub fn key(mut self, key: &'s [u8]) -> Self {
        self.keys.push(key);
        self
    }

    /// Adds the signer keys.
    pub fn keys(mut self, keys: impl IntoIterator<Item = &'s [u8]>)
                -> Self {
        keys.into_iter().for_each(|k| self.keys.push(k));
        self
    }

    /// Signs data.
    pub fn data(self, data: &[u8]) -> Result<Data> {
        let mut tmp = Vec::new();
        let mut args = vec!["sign".to_string()];
        if self.no_armor {
            args.push("--no-armor".into());
        }

        if let SignAs::Binary = self.as_ {
            // This is the default.  Omit it as a courtesy to
            // implementations that do not implement this parameter.
        } else {
            args.push("--as".into());
            args.push(self.as_.to_string());
        }

        for key in self.keys {
            args.push(self.sop.stash_bytes(key, &mut tmp)?);
        }

        let o = self.sop.run(&args[..], data)?;
        Ok(o.stdout.into())
    }
}

/// Builder for [`Sop::verify`].
pub struct Verify<'s> {
    sop: &'s Sop,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    certs: Vec<&'s [u8]>,
}

/// Builder for [`Sop::verify`].
pub struct VerifySignatures<'s> {
    verify: Verify<'s>,
    signatures: &'s [u8],
}

impl<'s> Verify<'s> {
    /// Makes SOP consider signatures before this date invalid.
    pub fn not_before(mut self, t: DateTime<Utc>) -> Self {
        self.not_before = Some(t);
        self
    }

    /// Makes SOP consider signatures after this date invalid.
    pub fn not_after(mut self, t: DateTime<Utc>) -> Self {
        self.not_after = Some(t);
        self
    }

    /// Adds the verification cert.
    pub fn cert(mut self, cert: &'s [u8]) -> Self {
        self.certs.push(cert);
        self
    }

    /// Adds the verification certs.
    pub fn certs(mut self, certs: impl IntoIterator<Item = &'s [u8]>)
                -> Self {
        certs.into_iter().for_each(|k| self.certs.push(k));
        self
    }

    /// Provides the signatures.
    pub fn signatures(self, signatures: &'s [u8]) -> VerifySignatures {
        VerifySignatures {
            verify: self,
            signatures,
        }
    }
}

impl VerifySignatures<'_> {
    /// Verifies the authenticity of `data`.
    pub fn data(self, data: &[u8]) -> Result<Vec<Verification>> {
        self.data_raw(data)
            .and_then(|data|
                      String::from_utf8(Vec::from(data)).map_err(Into::into))
            .and_then(|verifications| {
                let mut r = Vec::new();
                for v in verifications.trim_end().split('\n') {
                    r.push(v.parse()?);
                }
                Ok(r)
            })
    }

    /// Verifies the authenticity of `data` returning the raw result.
    pub fn data_raw(self, data: &[u8]) -> Result<Data> {
        let sop = self.verify.sop;
        let mut tmp = Vec::new();
        let mut args = vec!["verify".to_string()];
        if let Some(t) = self.verify.not_before {
            args.push("--not-before".into());
            args.push(t.format("%+").to_string());
        }
        if let Some(t) = self.verify.not_after {
            args.push("--not-after".into());
            args.push(t.format("%+").to_string());
        }

        args.push(sop.stash_bytes(self.signatures, &mut tmp)?);

        for cert in self.verify.certs {
            args.push(sop.stash_bytes(cert, &mut tmp)?);
        }

        let o = sop.run(&args[..], data)?;
        Ok(o.stdout.into())
    }
}

/// Builder for [`Sop::encrypt`].
pub struct Encrypt<'s> {
    sop: &'s Sop,
    no_armor: bool,
    as_: EncryptAs,
    passwords: Vec<&'s str>,
    sign_with: Vec<&'s [u8]>,
    certs: Vec<&'s [u8]>,
}

impl<'s> Encrypt<'s> {
    /// Disables armor encoding.
    pub fn no_armor(mut self) -> Self {
        self.no_armor = true;
        self
    }

    /// Sets encryption mode.
    pub fn as_(mut self, as_: EncryptAs) -> Self {
        self.as_ = as_;
        self
    }

    /// Adds the signer key.
    pub fn signer_key(mut self, key: &'s [u8]) -> Self {
        self.sign_with.push(key);
        self
    }

    /// Adds the signer keys.
    pub fn signer_keys(mut self, keys: impl IntoIterator<Item = &'s [u8]>)
                -> Self {
        keys.into_iter().for_each(|k| self.sign_with.push(k));
        self
    }

    /// Encrypts with the given password.
    pub fn with_password(mut self, password: &'s str) -> Self {
        self.passwords.push(password);
        self
    }

    /// Encrypts with the given passwords.
    pub fn with_passwords(mut self,
                          passwords: impl IntoIterator<Item = &'s str>)
                          -> Self {
        passwords.into_iter().for_each(|k| self.passwords.push(k));
        self
    }

    /// Encrypts with the given cert.
    pub fn cert(mut self, cert: &'s [u8]) -> Self {
        self.certs.push(cert);
        self
    }

    /// Encrypts with the given certs.
    pub fn certs(mut self, certs: impl IntoIterator<Item = &'s [u8]>)
                -> Self {
        certs.into_iter().for_each(|k| self.certs.push(k));
        self
    }

    /// Encrypts data.
    pub fn plaintext<P: AsRef<[u8]>>(self, plaintext: P) -> Result<Data> {
        let mut tmp = Vec::new();
        let mut args = vec!["encrypt".to_string()];
        if self.no_armor {
            args.push("--no-armor".into());
        }

        if let EncryptAs::Binary = self.as_ {
            // This is the default.  Omit it as a courtesy to
            // implementations that do not implement this parameter.
        } else {
            args.push("--as".into());
            args.push(self.as_.to_string());
        }

        for p in self.passwords {
            args.push("--with-password".into());
            args.push(self.sop.stash_bytes(p.as_bytes(), &mut tmp)?);
        }

        for key in self.sign_with {
            args.push("--sign-with".into());
            args.push(self.sop.stash_bytes(key, &mut tmp)?);
        }

        for cert in self.certs {
            args.push(self.sop.stash_bytes(cert, &mut tmp)?);
        }

        let o = self.sop.run(&args[..], plaintext)?;
        Ok(o.stdout.into())
    }
}

/// Builder for [`Sop::decrypt`].
pub struct Decrypt<'s> {
    verify: Verify<'s>,
    session_key_out: Option<&'s mut Option<Data>>,
    session_keys: Vec<&'s [u8]>,
    passwords: Vec<&'s str>,
    keys: Vec<&'s [u8]>,
}

impl<'s> Decrypt<'s> {
    /// Makes SOP consider signatures before this date invalid.
    pub fn verify_not_before(mut self, t: DateTime<Utc>) -> Self {
        self.verify.not_before = Some(t);
        self
    }

    /// Makes SOP consider signatures after this date invalid.
    pub fn verify_not_after(mut self, t: DateTime<Utc>) -> Self {
        self.verify.not_after = Some(t);
        self
    }

    /// Adds the verification cert.
    pub fn verify_cert(mut self, cert: &'s [u8]) -> Self {
        self.verify.certs.push(cert);
        self
    }

    /// Adds the verification certs.
    pub fn verify_certs(mut self, certs: impl IntoIterator<Item = &'s [u8]>)
                        -> Self {
        certs.into_iter().for_each(|k| self.verify.certs.push(k));
        self
    }

    /// Writes the decrypted session key to the given location.
    pub fn with_session_key_out(mut self,
                            session_key_out: &'s mut Option<Data>)
                            -> Self {
        self.session_key_out = Some(session_key_out);
        self
    }

    /// Tries to decrypt with the given session key.
    pub fn with_session_key(mut self, session_key: &'s [u8]) -> Self {
        self.session_keys.push(session_key);
        self
    }

    /// Tries to decrypt with the given session keys.
    pub fn with_session_keys(mut self,
                          session_keys: impl IntoIterator<Item = &'s [u8]>)
                          -> Self {
        session_keys.into_iter().for_each(|k| self.session_keys.push(k));
        self
    }

    /// Tries to decrypt with the given password.
    pub fn with_password(mut self, password: &'s str) -> Self {
        self.passwords.push(password);
        self
    }

    /// Tries to decrypt with the given passwords.
    pub fn with_passwords(mut self,
                          passwords: impl IntoIterator<Item = &'s str>)
                          -> Self {
        passwords.into_iter().for_each(|k| self.passwords.push(k));
        self
    }

    /// Adds the decryption key.
    pub fn key(mut self, key: &'s [u8]) -> Self {
        self.keys.push(key);
        self
    }

    /// Adds the decryption keys.
    pub fn keys(mut self, keys: impl IntoIterator<Item = &'s [u8]>)
                -> Self {
        keys.into_iter().for_each(|k| self.keys.push(k));
        self
    }

    /// Decrypts `ciphertext`, returning verification results and
    /// plaintexts.
    pub fn ciphertext(self, ciphertext: &[u8])
                      -> Result<(Vec<Verification>, Data)> {
        let (verification_raw, plaintext) =
            self.ciphertext_raw(ciphertext)?;

        let verifications = String::from_utf8(verification_raw.into())
            .map_err(Into::into)
            .and_then(|verifications| -> Result<_> {
                let mut r = Vec::new();
                if ! verifications.is_empty() {
                    for v in verifications.trim_end().split('\n') {
                        r.push(v.parse()?);
                    }
                }
                Ok(r)
            })?;

        Ok((verifications, plaintext))
    }

    /// Decrypts `ciphertext`, returning verification results and
    /// plaintexts.
    pub fn ciphertext_raw(self, ciphertext: &[u8]) -> Result<(Data, Data)> {
        let sop = self.verify.sop;
        let mut tmp = Vec::new();
        let mut args = vec!["decrypt".to_string()];

        let session_key_out =
            if let Some(out) = self.session_key_out {
                let p = sop.allocate_out_file(&mut tmp)?;
                args.push("--session-key-out".into());
                args.push(p.clone());
                Some((out, p))
            } else {
                None
            };

        for sk in self.session_keys {
            args.push("--with-session-key".into());
            args.push(sop.stash_bytes(
                openpgp::fmt::hex::encode(sk).as_bytes(), &mut tmp)?);
        }

        for p in self.passwords {
            args.push("--with-password".into());
            args.push(sop.stash_bytes(p.as_bytes(), &mut tmp)?);
        }

        let verify_out_raw =
            if ! self.verify.certs.is_empty() {
                let p = sop.allocate_out_file(&mut tmp)?;
                // XXX: At some point, we should start to use use
                // --verifications-out here.
                args.push("--verify-out".into());
                args.push(p.clone());
                Some(p)
            } else {
                None
            };

        for cert in self.verify.certs {
            args.push("--verify-with".into());
            args.push(sop.stash_bytes(cert, &mut tmp)?);
        }

        if let Some(t) = self.verify.not_before {
            args.push("--verify-not-before".into());
            args.push(t.format("%+").to_string());
        }
        if let Some(t) = self.verify.not_after {
            args.push("--verify-not-after".into());
            args.push(t.format("%+").to_string());
        }

        for key in self.keys {
            args.push(sop.stash_bytes(key, &mut tmp)?);
        }

        let o = sop.run(&args[..], ciphertext)?;

        if let Some((out, p)) = session_key_out {
            let bytes = std::fs::read(&p)
                .context("No session key written to --session-key-out")?;
            std::fs::remove_file(p)?;
            let string = std::str::from_utf8(&bytes)
                .context("Non UTF-8 session key written to --session-key-out")?;
            let sk = openpgp::fmt::hex::decode(&string)
                .context("Malformed session key written to --session-key-out")?;
            *out = Some(sk.into());
        }

        let verify_raw =
            if let Some(p) = verify_out_raw {
                let bytes = std::fs::read(&p)
                    .context("No verifications written to --verify-out")?;
                std::fs::remove_file(p)?;
                bytes.into()
            } else {
                Default::default()
            };

        Ok((verify_raw, o.stdout.into()))
    }
}

/// Builder for [`Sop::inline_verify`].
pub struct InlineVerify<'s> {
    sop: &'s Sop,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    certs: Vec<&'s [u8]>,
}

impl<'s> InlineVerify<'s> {
    /// Makes SOP consider signatures before this date invalid.
    pub fn not_before(mut self, t: DateTime<Utc>) -> Self {
        self.not_before = Some(t);
        self
    }

    /// Makes SOP consider signatures after this date invalid.
    pub fn not_after(mut self, t: DateTime<Utc>) -> Self {
        self.not_after = Some(t);
        self
    }

    /// Adds the verification cert.
    pub fn cert(mut self, cert: &'s [u8]) -> Self {
        self.certs.push(cert);
        self
    }

    /// Adds the verification certs.
    pub fn certs(mut self, certs: impl IntoIterator<Item = &'s [u8]>)
                -> Self {
        certs.into_iter().for_each(|k| self.certs.push(k));
        self
    }

    /// Verifies the authenticity of `data`.
    pub fn message(self, data: &[u8]) -> Result<(Vec<Verification>, Data)> {
        let (verification_raw, plaintext) =
            self.message_raw(data)?;

        let verifications = String::from_utf8(verification_raw.into())
            .map_err(Into::into)
            .and_then(|verifications| -> Result<_> {
                let mut r = Vec::new();
                if ! verifications.is_empty() {
                    for v in verifications.trim_end().split('\n') {
                        r.push(v.parse()?);
                    }
                }
                Ok(r)
            })?;

        Ok((verifications, plaintext))
    }

    /// Verifies the authenticity of `data` returning the raw result.
    pub fn message_raw(self, data: &[u8]) -> Result<(Data, Data)> {
        let mut tmp = Vec::new();
        let mut args = vec!["inline-verify".to_string()];
        let verifications_out = self.sop.allocate_out_file(&mut tmp)?;
        args.push("--verifications-out".into());
        args.push(verifications_out.clone());

        if let Some(t) = self.not_before {
            args.push("--not-before".into());
            args.push(t.format("%+").to_string());
        }
        if let Some(t) = self.not_after {
            args.push("--not-after".into());
            args.push(t.format("%+").to_string());
        }

        for cert in self.certs {
            args.push(self.sop.stash_bytes(cert, &mut tmp)?);
        }

        let o = self.sop.run(&args[..], data)?;

        let verifications_raw = std::fs::read(&verifications_out)
            .context("No verifications written to --verifications-out")?
            .into();
        std::fs::remove_file(verifications_out)?;

        Ok((verifications_raw, o.stdout.into()))
    }
}

/// Builder for [`Sop::armor`].
pub struct Armor<'s> {
    sop: &'s Sop,
    label: ArmorKind,
}

impl Armor<'_> {
    /// Overrides automatic detection of label.
    pub fn label(mut self, label: ArmorKind) -> Self {
        self.label = label;
        self
    }

    /// Armors `data`.
    pub fn data(self, data: &[u8]) -> Result<Data> {
        let mut args = vec!["armor".to_string()];

        if let ArmorKind::Auto = self.label {
            // This is the default.  Omit it as a courtesy to
            // implementations that do not implement this parameter.
        } else {
            args.push("--label".into());
            args.push(self.label.to_string());
        }

        let o = self.sop.run(&args[..], data)?;
        Ok(o.stdout.into())
    }
}

/// Builder for [`Sop::dearmor`].
pub struct Dearmor<'s> {
    sop: &'s Sop,
}

impl Dearmor<'_> {
    /// Dearmors `data`.
    pub fn data(self, data: &[u8]) -> Result<Data> {
        let o = self.sop.run(&["dearmor"], data)?;
        Ok(o.stdout.into())
    }
}

impl crate::OpenPGP for Sop {
    fn sop(&self) -> &Sop {
        self
    }

    fn version(&self) -> Result<Version> {
        Sop::version(self)
    }

    fn encrypt(&self, recipient: &[u8], plaintext: &[u8])
               -> Result<Data> {
        Sop::encrypt(self).cert(recipient).plaintext(plaintext)
    }

    fn decrypt(&self, recipient: &[u8], ciphertext: &[u8])
               -> Result<Data> {
        Ok(Sop::decrypt(self).key(recipient).ciphertext_raw(ciphertext)?.1)
    }

    fn sign_detached(&self, signer: &[u8], data: &[u8])
                     -> Result<Data> {
        Sop::sign(self).keys(vec![signer]).data(data)
    }

    fn verify_detached(&self, signer: &[u8], data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        Sop::verify(self).cert(signer).signatures(sig).data_raw(data)
    }

    fn generate_key(&self, userids: &[&str]) -> Result<Data> {
        Sop::generate_key(self).userids(userids.iter().cloned())
    }
}

/// (Backend, Version)-tuple supporting multiple versions per backend.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct Version {
    frontend: String,
    backend: Option<String>,
    extended: Option<String>,
    /// Combines frontend and backend.  Used when either is not
    /// descriptive enough but when extended is too verbose.
    summary: String,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.summary)
    }
}

#[derive(Debug)]
pub struct Verification {
    pub timestamp: DateTime<Utc>,
    pub signer: openpgp::Fingerprint,
    pub cert: openpgp::Fingerprint,
    pub comment: String,
}

impl Verification {
    pub fn expect_timestamp<T>(&self, _t: T)
                               -> Result<()>
    where T: Into<DateTime<Utc>>
    {
        unimplemented!()
    }
    pub fn summary(&self) -> Data {
        format!("Good signature from {:X}", self.cert).into_bytes().into()
    }
}

impl std::str::FromStr for Verification {
    type Err = SOPError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use SOPError::ProtocolViolation as E;
        let mut i = s.splitn(4, ' ');
        let timestamp = i.next().ok_or(E("Timestamp missing".into()))
            .and_then(parse_iso8601)?;
        let signer = i.next().ok_or(E("Signer fingerprint missing".into()))
            .and_then(|s| {
                openpgp::Fingerprint::from_str(s)
                    .map_err(|e| E(format!("Malformed fingerprint: {}", e)))
            })?;
        let cert = i.next().ok_or(E("Cert fingerprint missing".into()))
            .and_then(|s| {
                openpgp::Fingerprint::from_str(s)
                    .map_err(|e| E(format!("Malformed fingerprint: {}", e)))
            })?;
        let comment = i.next().unwrap_or_default().to_string();
        Ok(Verification {
            timestamp,
            signer,
            cert,
            comment,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SignAs {
    Binary,
    Text,
}

impl Default for SignAs {
    fn default() -> Self {
        SignAs::Binary
    }
}

impl std::str::FromStr for SignAs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "binary" => Ok(SignAs::Binary),
            "text" => Ok(SignAs::Text),
            _ => Err(anyhow::anyhow!(
                "{:?}, expected one of {{binary|text}}", s)),
        }
    }
}

impl fmt::Display for SignAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignAs::Binary => f.write_str("binary"),
            SignAs::Text => f.write_str("text"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EncryptAs {
    Binary,
    Text,
    MIME,
}

impl Default for EncryptAs {
    fn default() -> Self {
        EncryptAs::Binary
    }
}

impl std::str::FromStr for EncryptAs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "binary" => Ok(EncryptAs::Binary),
            "text" => Ok(EncryptAs::Text),
            "mime" => Ok(EncryptAs::MIME),
            _ => Err(anyhow::anyhow!(
                "{}, expected one of {{binary|text|mime}}", s)),
        }
    }
}

impl fmt::Display for EncryptAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncryptAs::Binary => f.write_str("binary"),
            EncryptAs::Text => f.write_str("text"),
            EncryptAs::MIME => f.write_str("mime"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ArmorKind {
    Auto,
    Sig,
    Key,
    Cert,
    Message,
}

impl Default for ArmorKind {
    fn default() -> Self {
        ArmorKind::Auto
    }
}

impl std::str::FromStr for ArmorKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(ArmorKind::Auto),
            "sig" => Ok(ArmorKind::Sig),
            "key" => Ok(ArmorKind::Key),
            "cert" => Ok(ArmorKind::Cert),
            "message" => Ok(ArmorKind::Message),
            _ => Err(anyhow::anyhow!(
                "{:?}, expected one of \
                 {{auto|sig|key|cert|message}}", s)),
        }
    }
}

impl fmt::Display for ArmorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArmorKind::Auto => f.write_str("auto"),
            ArmorKind::Sig => f.write_str("sig"),
            ArmorKind::Key => f.write_str("key"),
            ArmorKind::Cert => f.write_str("cert"),
            ArmorKind::Message => f.write_str("message"),
        }
    }
}

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str) -> std::result::Result<DateTime<Utc>, SOPError>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y%m%dT%H%M%S%#z",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d, Utc));
            }
        }
    }
    Err(SOPError::ProtocolViolation(
        format!("Malformed ISO8601 timestamp: {}", s)))
}

#[test]
fn test_parse_iso8601() {
    parse_iso8601("2017-03-04T13:25:35Z").unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30").unwrap();
    parse_iso8601("20170304T132535Z").unwrap();
    parse_iso8601("20170304T132535+0830").unwrap();
}

/// Errors defined by the Stateless OpenPGP Protocol.
#[derive(thiserror::Error, Debug)]
pub enum SOPError {
    /// No acceptable signatures found ("sop verify").
    #[error("No acceptable signatures found")]
    NoSignature,

    /// Asymmetric algorithm unsupported ("sop encrypt").
    #[error("Asymmetric algorithm unsupported")]
    UnsupportedAsymmetricAlgo,

    /// Certificate not encryption-capable (e.g., expired, revoked,
    /// unacceptable usage flags) ("sop encrypt").
    #[error("Certificate not encryption-capable")]
    CertCannotEncrypt,

    /// Missing required argument.
    #[error("Missing required argument")]
    MissingArg,

    /// Incomplete verification instructions ("sop decrypt").
    #[error("Incomplete verification instructions")]
    IncompleteVerification,

    /// Unable to decrypt ("sop decrypt").
    #[error("Unable to decrypt")]
    CannotDecrypt,

    /// Non-"UTF-8" or otherwise unreliable password ("sop encrypt").
    #[error("Non-UTF-8 or otherwise unreliable password")]
    PasswordNotHumanReadable,

    /// Unsupported option.
    #[error("Unsupported option")]
    UnsupportedOption,

    /// Invalid data type (no secret key where "KEY" expected, etc).
    #[error("Invalid data type")]
    BadData,

    /// Non-text input where text expected.
    #[error("Non-text input where text expected")]
    ExpectedText,

    /// Output file already exists.
    #[error("Output file already exists")]
    OutputExists,

    /// Input file does not exist.
    #[error("Input file does not exist")]
    MissingInput,

    /// A "KEY" input is protected (locked) with a password, and "sop" cannot
    /// unlock it.
    #[error("A KEY input is protected with a password")]
    KeyIsProtected,

    /// Unsupported subcommand.
    #[error("Unsupported subcommand")]
    UnsupportedSubcommand,

    /// An indirect parameter is a special designator (it starts with "@") but
    /// "sop" does not know how to handle the prefix.
    #[error("An indirect parameter is a special designator with unknown prefix")]
    UnsupportedSpecialPrefix,

    /// A indirect input parameter is a special designator (it starts with
    /// "@"), and a filename matching the designator is actually present.
    #[error("A indirect input parameter is a special designator matches file")]
    AmbiguousInput,

    /// An unknown error occurred.
    ///
    /// The returned status did not correspond to any known SOP error code.
    #[error("Unknown error code '{}'", _0)]
    Unknown(i32),

    /// The child process was terminated by a signal.
    #[error("Terminated by signal '{}'", _0)]
    Signal(i32),

    /// An error occurred communicating with the child process.
    #[error("Communicating with child failed")]
    IoError(#[from] std::io::Error),

    /// Protocol violation.
    #[error("Protocol violation: {}", _0)]
    ProtocolViolation(String),
}

impl From<ExitStatus> for SOPError {
    fn from(e: ExitStatus) -> Self {
        use SOPError::*;
        if let Some(status) = e.code() {
            match status {
                3 => NoSignature,
                13 => UnsupportedAsymmetricAlgo,
                17 => CertCannotEncrypt,
                19 => MissingArg,
                23 => IncompleteVerification,
                29 => CannotDecrypt,
                31 => PasswordNotHumanReadable,
                37 => UnsupportedOption,
                41 => BadData,
                53 => ExpectedText,
                59 => OutputExists,
                61 => MissingInput,
                67 => KeyIsProtected,
                69 => UnsupportedSubcommand,
                71 => UnsupportedSpecialPrefix,
                73 => AmbiguousInput,
                n => Unknown(n),
            }
        } else if let Some(signal) = e.signal() {
            Signal(signal)
        } else {
            unreachable!("On unix, there is either a status or a signal")
        }
    }
}

/// A [`SOPError`] with data written to stdout and stderr.
///
/// This is used by [`Sop::run`] to communicate both the processes
/// output and any error condition.
#[derive(thiserror::Error, Debug)]
#[error("{}\nstdout:\n~~~snip~~~\n{}~~~snip~~~\nstderr:\n~~~snip~~~\n{}~~~snip~~~\n",
        source,
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr))]
pub struct ErrorWithOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub source: SOPError,
}

impl ErrorWithOutput {
    fn new(source: impl Into<SOPError>, output: process::Output)
           -> Self {
        Self {
            stdout: output.stdout,
            stderr: output.stderr,
            source: source.into(),
        }
    }
}

impl From<io::Error> for ErrorWithOutput {
    fn from(e: io::Error) -> Self {
        Self {
            stdout: Default::default(),
            stderr: Default::default(),
            source: SOPError::IoError(e),
        }
    }
}

impl std::ops::Deref for ErrorWithOutput {
    type Target = SOPError;
    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_sop() -> Result<Sop> {
        for name in &[
            "sqop",
            "dkg-sop",
            "gosop",
            "pgpainless-sop",
            "rnp-sop",
        ] {
            if let Ok(s) = which::which(name)
                .map_err(Into::into)
                .and_then(|p| Sop::new(p))
            {
                if let Ok(v) = s.version() {
                    eprintln!("Using {} to run the tests.", v);
                    return Ok(s);
                }
            }
        }

        Err(anyhow::anyhow!("Could not find SOP implementation for use in the tests"))
    }

    /// This is the example from the SOP spec:
    ///
    ///     sop generate-key "Alice Lovelace <alice@openpgp.example>" > alice.sec
    ///     sop extract-cert < alice.sec > alice.pgp
    ///
    ///     sop sign --as=text alice.sec < statement.txt > statement.txt.asc
    ///     sop verify announcement.txt.asc alice.pgp < announcement.txt
    ///
    ///     sop encrypt --sign-with=alice.sec bob.pgp < msg.eml > encrypted.asc
    ///     sop decrypt alice.sec < ciphertext.asc > cleartext.out
    #[test]
    fn sop_examples() -> Result<()> {
        let sop = find_sop()?;

        let alice_sec = sop
            .generate_key()
            .userids(vec!["Alice Lovelace <alice@openpgp.example>"])?;
        let alice_pgp = sop
            .extract_cert()
            .key(&alice_sec)?;

        let bob_sec = sop
            .generate_key()
            .userids(vec!["Bob Babbage <bob@openpgp.example>"])?;
        let bob_pgp = sop
            .extract_cert()
            .key(&bob_sec)?;

        let statement = b"Hello World :)";
        let statement_asc = sop
            .sign()
            .as_(SignAs::Text)
            .key(&alice_sec)
            .data(statement)?;
        let verifications = sop
            .verify()
            .cert(&alice_pgp)
            .signatures(&statement_asc)
            .data(statement).unwrap();
        assert_eq!(verifications.len(), 1);

        let ciphertext = sop
            .encrypt()
            .signer_key(&alice_sec)
            .cert(&bob_pgp)
            .plaintext(statement).unwrap();
        let plaintext = sop
            .decrypt()
            .key(&bob_sec)
            .ciphertext(&ciphertext).unwrap();
        assert_eq!(&plaintext.1[..], statement);

        Ok(())
    }
}
