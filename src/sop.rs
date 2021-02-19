use std::collections::HashMap;
use std::fmt;
use std::process::{self, ExitStatus};
use std::os::unix::process::ExitStatusExt;
use std::io::Write;

use std::path::{Path, PathBuf};
use tempfile::{TempDir, NamedTempFile};
use chrono::{DateTime, offset::Utc};
use anyhow::Context;

use sequoia_openpgp as openpgp;

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
        let write_result =
            child.stdin.as_mut().unwrap().write_all(input.as_ref());
        let o = child.wait_with_output()?;

        if let Err(e) = write_result {
            Err(Error::EngineError(
                e.into(),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string())
                .into())
        } else if o.status.success() {
            Ok(o)
        } else {
            Err(Error::EngineError(
                SOPError::from(o.status),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string())
                .into())
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

impl Sop {
    /// Gets version information.
    pub fn version(&self) -> Result<crate::Version> {
        let o = self.run(&["version"], &[])?;
        let stdout = String::from_utf8_lossy(&o.stdout);
        let mut name =
            stdout.trim().split(' ').nth(0).unwrap_or("unknown").to_string();
        if name.to_lowercase().ends_with("-sop") {
            name =
                String::from_utf8(name.as_bytes()[..name.len() - 4].to_vec())
                .unwrap();
        }

        let version =
            stdout.trim().split(' ').nth(1).unwrap_or("unknown").to_string();
        Ok(Version {
            implementation: Implementation::Sop(name),
            version,
        })
    }

    /// Generates a Secret Key.
    pub fn generate_key<'u>(&self,
                            no_armor: bool,
                            userids: impl IntoIterator<Item = &'u str>)
                            -> Result<Data> {
        let mut args = vec!["generate-key"];
        if no_armor {
            args.push("--no-armor");
        }
        for u in userids {
            args.push(u);
        }
        let o = self.run(&args[..], &[])?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Extracts a Certificate from a Secret Key.
    pub fn extract_cert(&self,
                        no_armor: bool,
                        key: &[u8])
                        -> Result<Data> {
        let mut args = vec!["extract-cert"];
        if no_armor {
            args.push("--no-armor");
        }
        let o = self.run(&args[..], key)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Creates Detached Signatures.
    pub fn sign<'k>(&self,
                    no_armor: bool,
                    as_: SignAs,
                    keys: impl IntoIterator<Item = &'k [u8]>,
                    data: &[u8])
                    -> Result<Data> {
        let mut tmp = Vec::new();
        let mut args = vec!["sign".to_string()];
        if no_armor {
            args.push("--no-armor".into());
        }

        if let SignAs::Binary = as_ {
            // This is the default.  Omit it as a courtesy to
            // implementations that do not implement this parameter.
        } else {
            args.push("--as".into());
            args.push(as_.to_string());
        }

        for key in keys {
            args.push(self.stash_bytes(key, &mut tmp)?);
        }

        let o = self.run(&args[..], data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Verifies Detached Signatures.
    pub fn verify<'c>(&self,
                      not_before: Option<DateTime<Utc>>,
                      not_after: Option<DateTime<Utc>>,
                      signatures: &[u8],
                      certs: impl IntoIterator<Item = &'c [u8]>,
                      data: &[u8])
                      -> Result<Vec<Verification>> {
        self.verify_raw(not_before, not_after, signatures, certs, data)
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

    /// Verifies Detached Signatures.
    ///
    /// This provides unparsed signature verification output.
    pub fn verify_raw<'c>(&self,
                          not_before: Option<DateTime<Utc>>,
                          not_after: Option<DateTime<Utc>>,
                          signatures: &[u8],
                          certs: impl IntoIterator<Item = &'c [u8]>,
                          data: &[u8])
                          -> Result<Data> {
        let mut tmp = Vec::new();
        let mut args = vec!["verify".to_string()];
        if let Some(t) = not_before {
            args.push("--not-before".into());
            args.push(t.format("%+").to_string());
        }
        if let Some(t) = not_after {
            args.push("--not-after".into());
            args.push(t.format("%+").to_string());
        }

        args.push(self.stash_bytes(signatures, &mut tmp)?);

        for cert in certs {
            args.push(self.stash_bytes(cert, &mut tmp)?);
        }

        let o = self.run(&args[..], data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Encrypts a Message.
    pub fn encrypt<'p, 's, 'c>(&self,
                               no_armor: bool,
                               as_: EncryptAs,
                               with_password: impl IntoIterator<Item = &'p str>,
                               sign_with: impl IntoIterator<Item = &'s [u8]>,
                               certs: impl IntoIterator<Item = &'c [u8]>,
                               plaintext: &[u8])
                               -> Result<Data> {
        let mut tmp = Vec::new();
        let mut args = vec!["encrypt".to_string()];
        if no_armor {
            args.push("--no-armor".into());
        }

        if let EncryptAs::Binary = as_ {
            // This is the default.  Omit it as a courtesy to
            // implementations that do not implement this parameter.
        } else {
            args.push("--as".into());
            args.push(as_.to_string());
        }

        for p in with_password {
            args.push("--with-password".into());
            args.push(p.into());
        }

        for key in sign_with {
            args.push("--sign-with".into());
            args.push(self.stash_bytes(key, &mut tmp)?);
        }

        for cert in certs {
            args.push(self.stash_bytes(cert, &mut tmp)?);
        }

        let o = self.run(&args[..], plaintext)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Decrypts a Message.
    pub fn decrypt<'s, 'p, 'c, 'k>(
        &self,
        session_key_out: Option<&mut Option<Data>>,
        with_session_key: impl IntoIterator<Item = &'s [u8]>,
        with_password: impl IntoIterator<Item = &'p str>,
        verify_with: impl IntoIterator<Item = &'c [u8]>,
        verify_not_before: Option<DateTime<Utc>>,
        verify_not_after: Option<DateTime<Utc>>,
        keys: impl IntoIterator<Item = &'k [u8]>,
        ciphertext: &[u8])
        -> Result<(Vec<Verification>, Data)>
    {
        let mut verifications = None;
        let plaintext =
            self.decrypt_raw(session_key_out, with_session_key,
                             with_password,
                             Some(&mut verifications),
                             verify_with,
                             verify_not_before,
                             verify_not_after,
                             keys,
                             ciphertext)?;
        let verifications = String::from_utf8(
            verifications.map(Vec::from).unwrap_or_else(Vec::new))
            .map_err(Into::into)
            .and_then(|verifications| -> Result<_> {
                let mut r = Vec::new();
                for v in verifications.trim_end().split('\n') {
                    r.push(v.parse()?);
                }
                Ok(r)
            })?;

        Ok((verifications, plaintext))
    }

    /// Decrypts a Message.
    ///
    /// This provides unparsed signature verification output.
    pub fn decrypt_raw<'s, 'p, 'c, 'k>(
        &self,
        session_key_out: Option<&mut Option<Data>>,
        with_session_key: impl IntoIterator<Item = &'s [u8]>,
        with_password: impl IntoIterator<Item = &'p str>,
        verify_out_raw: Option<&mut Option<Data>>,
        verify_with: impl IntoIterator<Item = &'c [u8]>,
        verify_not_before: Option<DateTime<Utc>>,
        verify_not_after: Option<DateTime<Utc>>,
        keys: impl IntoIterator<Item = &'k [u8]>,
        ciphertext: &[u8])
        -> Result<Data>
    {
        let mut tmp = Vec::new();
        let mut args = vec!["decrypt".to_string()];

        let session_key_out =
            if let Some(out) = session_key_out {
                let p = self.allocate_out_file(&mut tmp)?;
                args.push("--session-key-out".into());
                args.push(p.clone());
                Some((out, p))
            } else {
                None
            };

        for sk in with_session_key {
            args.push("--with-session-key".into());
            args.push(openpgp::fmt::hex::encode(sk));
        }

        for p in with_password {
            args.push("--with-password".into());
            args.push(p.into());
        }

        let verify_out_raw =
            if let Some(out) = verify_out_raw {
                let p = self.allocate_out_file(&mut tmp)?;
                args.push("--verify-out".into());
                args.push(p.clone());
                Some((out, p))
            } else {
                None
            };

        for cert in verify_with {
            args.push("--verify-with".into());
            args.push(self.stash_bytes(cert, &mut tmp)?);
        }

        if let Some(t) = verify_not_before {
            args.push("--verify-not-before".into());
            args.push(t.format("%+").to_string());
        }
        if let Some(t) = verify_not_after {
            args.push("--verify-not-after".into());
            args.push(t.format("%+").to_string());
        }

        for key in keys {
            args.push(self.stash_bytes(key, &mut tmp)?);
        }

        let o = self.run(&args[..], ciphertext)?;

        if let Some((out, p)) = session_key_out {
            let bytes = std::fs::read(&p)
                .context("No session key written to --session-key-out")?;
            std::fs::remove_file(p)?;
            let string = std::str::from_utf8(&bytes)
                .context("Non UTF-8 session key written to --session-key-out")?;
            let sk = openpgp::fmt::hex::decode(&string)
                .context("Malformed session key written to --session-key-out")?;
            *out = Some(sk.into_boxed_slice());
        }

        if let Some((out, p)) = verify_out_raw {
            let bytes = std::fs::read(&p)
                .context("No verifications written to --verify-out")?;
            std::fs::remove_file(p)?;
            *out = Some(bytes.into_boxed_slice());
        }

        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Converts binary OpenPGP data to ASCII
    pub fn armor(&self, label: ArmorKind, data: &[u8]) -> Result<Data> {
        let mut args = vec!["armor".to_string()];

        if let ArmorKind::Auto = label {
            // This is the default.  Omit it as a courtesy to
            // implementations that do not implement this parameter.
        } else {
            args.push("--label".into());
            args.push(label.to_string());
        }

        let o = self.run(&args[..], data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }

    /// Converts ASCII OpenPGP data to binary
    pub fn dearmor(&self, data: &[u8]) -> Result<Data> {
        let o = self.run(&["dearmor"], data)?;
        Ok(o.stdout.clone().into_boxed_slice())
    }
}

impl crate::OpenPGP for Sop {
    fn new_context(&self) -> Result<Box<dyn crate::OpenPGP>> {
        Self::new(&self.sop, &self.env)
            .map(|i| -> Box<dyn crate::OpenPGP> { Box::new(i) })
    }

    fn version(&self) -> Result<crate::Version> {
        Sop::version(self)
    }

    fn encrypt(&mut self, recipient: &[u8], plaintext: &[u8])
               -> Result<Box<[u8]>> {
        Sop::encrypt(self, false, EncryptAs::Binary, None, None,
                     vec![recipient], plaintext)
    }

    fn decrypt(&mut self, recipient: &[u8], ciphertext: &[u8])
               -> Result<Box<[u8]>> {
        Sop::decrypt_raw(self, None, None, None, None, None, None, None,
                         vec![recipient], ciphertext)
    }

    fn sign_detached(&mut self, signer: &[u8], data: &[u8])
                     -> Result<Data> {
        Sop::sign(self, false, SignAs::Binary, vec![signer], data)
    }

    fn verify_detached(&mut self, signer: &[u8], data: &[u8],
                       sig: &[u8])
                       -> Result<Data> {
        Sop::verify_raw(self, None, None, sig, vec![signer], data)
    }

    fn generate_key(&mut self, userids: &[&str]) -> Result<Data> {
        Sop::generate_key(self, false, userids.iter().cloned())
    }
}

pub struct Verification {
    pub timestamp: DateTime<Utc>,
    pub signer: openpgp::Fingerprint,
    pub cert: openpgp::Fingerprint,
    pub comment: String,
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
