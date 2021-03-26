use std::io::Write as _;
use std::fmt::Write as _;
use anyhow::Context;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        ConsumerTest,
        Expectation,
        Test,
        TestMatrix,
    },
};

fn mangle_armor<D>(data: D)
                   -> Result<Vec<(String, Data, Option<Expectation>)>>
where D: AsRef<[u8]>,
{
    let data = data.as_ref();
    // Data as Vec<u8>.
    let data = data.to_vec();
    // Data as String.
    let datas =
        String::from_utf8(data.to_vec()).unwrap();
    // Data as Vec<&str>.
    let datal = datas.lines().collect::<Vec<_>>();
    // Position of the empty line separating header and body.
    let empty_line = datal.iter().position(|l| *l == "").unwrap();

    fn quote<'a, S: AsRef<str>>(l: impl Iterator<Item = S> + 'a,
                                prefix: &'a str)
                                -> impl Iterator<Item = String> + 'a {
        l.map(move |l| format!("{}{}", prefix, l.as_ref()))
    }

    fn join<S: AsRef<str>>(l: impl Iterator<Item = S>, suffix: &str) -> Data
    {
        let l = l.map(|l| l.as_ref().to_string()).collect::<Vec<_>>();
        l.join(suffix).into_bytes().into()
    }

    Ok(vec![
        ("Not mangled".into(),
         data.clone().into(),
         Some(Ok("Base case".into()))),

        ("\\r\\n line endings".into(),
         join(datal.iter(), "\n"),
         Some(Ok("Interoperability concern".into()))),

        ("Blank line with space".into(),
         {
             let mut l = datal.clone();
             l[empty_line] = " ";
             join(l.iter(), "\n")
         },
         Some(Ok("Interoperability concern".into()))),

        ("Blank line with ' \\t\\r'".into(),
         {
             let mut l = datal.clone();
             l[empty_line] = " \t\r";
             join(l.iter(), "\n")
         },
         Some(Ok("Interoperability concern".into()))),

        ("Blank line with ' \\t\\r\\v\\f'".into(),
         {
             let mut l = datal.clone();
             l[empty_line] = " \t\r\x0b\x0c";
             join(l.iter(), "\n")
         },
         Some(Ok("Interoperability concern".into()))),

        ("Unknown header key".into(),
         {
             let mut l = datal.clone();
             l.insert(1, "Unknown: blabla");
             join(l.iter(), "\n")
         },
         Some(Ok("Interoperability concern".into()))),

        ("Very long header key".into(),
         {
             let mut comment = "Comment: ".to_string();
             for _ in 0..64 {
                 write!(comment, "0123456789abcde").unwrap();
             }
             let mut l = datal.clone();
             l.insert(1, &comment);
             join(l.iter(), "\n")
         },
         Some(Ok("Interoperability concern".into()))),

        ("No checksum".into(),
         {
             let mut l = datal.clone();
             l.remove(datal.len() - 2);
             join(l.iter(), "\n")
         },
         Some(Ok("Interoperability concern".into()))),

        ("No newlines in body".into(),
         join(datal.iter().take(3).map(|l| l.to_string()).chain(
             Some(datal[3..datal.len() - 2].join(""))).chain(
             datal[datal.len() - 2..].iter().map(|l| l.to_string())),
              "\n"),
         None),

        ("Spurious spaces in body".into(),
         {
             let mut b = data.clone();
             b.insert(77 + 0 * 65, b' ');
             b.insert(77 + 1 * 65, b'\n');
             b.insert(77 + 2 * 65, b'\t');
             b.insert(77 + 3 * 65, 0x0b);
             b.into()
         },
         None),

        ("Leading space".into(),
         join(quote(datal.iter(), " "), "\n"),
         None),

        ("Leading space, ends trimmed".into(),
         join(quote(datal.iter(), " ").map(|l| l.trim_end().to_string()),
              "\n"),
         None),

        ("Trailing space".into(),
         join(datal.iter(), " \n"),
         None),

        ("Double spaced".into(),
         join(datal.iter(), "\n\n"),
         None),

        ("Newlines replaced by spaces".into(),
         datas.replace("\n", " ").into_bytes().into(),
         None),

        ("Quoted with '> '".into(),
         join(quote(datal.iter(), "> "), "\n"),
         None),

        ("Quoted with '> ', ends trimmed".into(),
         join(quote(datal.iter(), "> ").map(|l| l.trim_end().to_string()),
              "\n"),
         None),

        ("Quoted with '] } >>> '".into(),
         join(quote(datal.iter(), "] } >>> "), "\n"),
         None),

        ("Missing '-' in header".into(),
         datas.clone().replacen("-", "", 1).into_bytes().into(),
         None),

        ("Unicode hyphens '‐'".into(),
         datas.clone().replace("-", "‐").into_bytes().into(),
         None),

        ("No hyphens".into(),
         datas.clone().replace("-", "").into_bytes().into(),
         None),

        ("Quoted-printable '=' -> '=3D'".into(),
         datas.clone().replace("=", "=3D").into_bytes().into(),
         None),

        ("Dash-escaped frames".into(),
         datas.clone().replace("-----B", "- -----B")
         .replace("-----E", "- -----E").into_bytes().into(),
         None),

        ("Missing header".into(),
         {
             let mut l = datal.clone();
             l.remove(0);
             join(l.iter(), "\n")
         },
         None),

        ("Missing blank line".into(),
         {
             let mut l = datal.clone();
             l.remove(2);
             join(l.iter(), "\n")
         },
         None),

        ("Missing footer".into(),
         {
             let mut l = datal.clone();
             l.remove(datal.len() - 1);
             join(l.iter(), "\n")
         },
         None),

        ("Bare base64 body".into(),
         {
             let mut l = datal.clone();
             l.remove(datal.len() - 1); // Footer.
             l.remove(datal.len() - 2); // Checksum.
             l.remove(0); // Header.
             l.remove(0); // Comment.
             l.remove(0); // Separator.
             join(l.iter(), "\n")
         },
         None),

        ("Bad checksum".into(),
         {
             let mut l = datal.clone();
             l[datal.len() - 2] = "=AAAA".into();
             join(l.iter(), "\n")
         },
         None),
    ])
}

/// Explores how robust the ASCII Armor reader is when reading KEYs.
pub struct MangledArmoredKey {
}

impl MangledArmoredKey {
    pub fn new() -> Result<MangledArmoredKey> {
        Ok(MangledArmoredKey {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for MangledArmoredKey {
    fn title(&self) -> String {
        "Mangled ASCII Armored Key".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>ASCII Armor is supposed to protect OpenPGP data in \
          transit, but unfortunately it can be a source of brittleness \
          if the Armor parser isn't sufficiently robust.</p>\
          \
          <p>This test mangles Bob's ASCII Armored key, and \
          tries to decrypt the text <code>{}</code>.</p>",
          String::from_utf8(self.message().into()).unwrap())
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MangledArmoredKey {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        mangle_armor(data::certificate("bob-secret.pgp"))
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(data::certificate("bob.pgp"),
                                     self.message())
            .context("Encryption failed")?;
        pgp.decrypt(artifact, &ciphertext)
            .context("Decryption failed")
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == self.message() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                self.message(), artifact))
        }
    }
}

/// Explores how robust the ASCII Armor reader is when reading CERTs.
pub struct MangledArmoredCert {
}

impl MangledArmoredCert {
    pub fn new() -> Result<MangledArmoredCert> {
        Ok(MangledArmoredCert {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for MangledArmoredCert {
    fn title(&self) -> String {
        "Mangled ASCII Armor".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>ASCII Armor is supposed to protect OpenPGP data in \
          transit, but unfortunately it can be a source of brittleness \
          if the Armor parser isn't sufficiently robust.</p>\
          \
          <p>This test mangles Bob's ASCII Armored certificate, and \
          tries to encrypt the text <code>{}</code>.</p>",
          String::from_utf8(self.message().into()).unwrap())
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MangledArmoredCert {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        mangle_armor(data::certificate("bob.pgp"))
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(artifact, self.message())
            .context("Encryption failed")?;
        pgp.decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
            .context("Decryption failed")
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == self.message() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                self.message(), artifact))
        }
    }
}

/// Explores how robust the ASCII Armor reader is when reading
/// CIPHERTEXTs.
pub struct MangledArmoredCiphertext {
}

impl MangledArmoredCiphertext {
    pub fn new() -> Result<MangledArmoredCiphertext> {
        Ok(MangledArmoredCiphertext {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for MangledArmoredCiphertext {
    fn title(&self) -> String {
        "Mangled ASCII Armored Ciphertexts".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>ASCII Armor is supposed to protect OpenPGP data in \
          transit, but unfortunately it can be a source of brittleness \
          if the Armor parser isn't sufficiently robust.</p>\
          \
          <p>This test mangles the ASCII Armored ciphertext decrypting \
          to the text <code>{}</code>.</p>",
          String::from_utf8(self.message().into()).unwrap())
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MangledArmoredCiphertext {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use sequoia_openpgp::{
            Cert,
            parse::Parse,
            policy::StandardPolicy,
            serialize::stream::*,
        };
        let cert = Cert::from_bytes(data::certificate("bob.pgp"))?;
        let p = &StandardPolicy::new();
        let recipients =
            cert.keys().with_policy(p, None).supported().alive().revoked(false)
            .for_transport_encryption();
        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;
        let message = Encryptor::for_recipients(message, recipients).build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(self.message())?;
        message.finalize()?;
        mangle_armor(sink)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
            .context("Decryption failed")
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == self.message() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                self.message(), artifact))
        }
    }
}

/// Explores how robust the ASCII Armor reader is when reading
/// SIGNATUREs.
pub struct MangledArmoredSignature {
}

impl MangledArmoredSignature {
    pub fn new() -> Result<MangledArmoredSignature> {
        Ok(MangledArmoredSignature {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for MangledArmoredSignature {
    fn title(&self) -> String {
        "Mangled ASCII Armored Signatures".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>ASCII Armor is supposed to protect OpenPGP data in \
          transit, but unfortunately it can be a source of brittleness \
          if the Armor parser isn't sufficiently robust.</p>\
          \
          <p>This test mangles the ASCII Armored signature over \
          the text <code>{}</code>.</p>",
          String::from_utf8(self.message().into()).unwrap())
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MangledArmoredSignature {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use sequoia_openpgp::{
            Cert,
            armor::Kind,
            parse::Parse,
            policy::StandardPolicy,
            serialize::stream::*,
        };
        let cert = Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let p = &StandardPolicy::new();
        let signer =
            cert.keys().with_policy(p, None).supported().alive().revoked(false)
            .secret()
            .for_signing()
            .nth(0).unwrap()
            .key().clone().into_keypair()?;
        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).kind(Kind::Signature).build()?;
        let mut message = Signer::new(message, signer).detached().build()?;
        message.write_all(self.message())?;
        message.finalize()?;
        mangle_armor(sink)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(data::certificate("bob.pgp"), self.message(),
                            artifact)
            .context("Verification failed")
    }
}
