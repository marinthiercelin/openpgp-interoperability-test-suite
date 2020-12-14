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

/// Explores how robust the ASCII Armor reader is.
pub struct MangledArmor {
}

impl MangledArmor {
    pub fn new() -> Result<MangledArmor> {
        Ok(MangledArmor {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for MangledArmor {
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MangledArmor {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let bob = data::certificate("bob.pgp").to_vec();
        let bobs =
            String::from_utf8(data::certificate("bob.pgp").to_vec()).unwrap();
        let bobl = bobs.lines().collect::<Vec<_>>();

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
             bob.clone().into(),
             Some(Ok("Base case".into()))),

            ("\\r\\n line endings".into(),
             join(bobl.iter(), "\n"),
             Some(Ok("Interoperability concern".into()))),

            ("Blank line with space".into(),
             {
                 let mut l = bobl.clone();
                 l[2] = " ";
                 join(l.iter(), "\n")
             },
             Some(Ok("Interoperability concern".into()))),

            ("Blank line with ' \\t\\r'".into(),
             {
                 let mut l = bobl.clone();
                 l[2] = " \t\r";
                 join(l.iter(), "\n")
             },
             Some(Ok("Interoperability concern".into()))),

            ("Blank line with ' \\t\\r\\v\\f'".into(),
             {
                 let mut l = bobl.clone();
                 l[2] = " \t\r\x0b\x0c";
                 join(l.iter(), "\n")
             },
             Some(Ok("Interoperability concern".into()))),

            ("Unknown header key".into(),
             {
                 let mut l = bobl.clone();
                 l[1] = "Unknown: blabla";
                 join(l.iter(), "\n")
             },
             Some(Ok("Interoperability concern".into()))),

            ("Very long header key".into(),
             {
                 let mut comment = "Comment: ".to_string();
                 for _ in 0..64 {
                     write!(comment, "0123456789abcde").unwrap();
                 }
                 let mut l = bobl.clone();
                 l[1] = &comment;
                 join(l.iter(), "\n")
             },
             Some(Ok("Interoperability concern".into()))),

            ("No checksum".into(),
             {
                 let mut l = bobl.clone();
                 l.remove(bobl.len() - 2);
                 join(l.iter(), "\n")
             },
             Some(Ok("Interoperability concern".into()))),

            ("No newlines in body".into(),
             join(bobl.iter().take(3).map(|l| l.to_string()).chain(
                 Some(bobl[3..bobl.len() - 2].join(""))).chain(
                 bobl[bobl.len() - 2..].iter().map(|l| l.to_string())),
                  "\n"),
             None),

            ("Spurious spaces in body".into(),
             {
                 let mut b = bob.clone();
                 b.insert(77 + 0 * 65, b' ');
                 b.insert(77 + 1 * 65, b'\n');
                 b.insert(77 + 2 * 65, b'\t');
                 b.insert(77 + 3 * 65, 0x0b);
                 b.into()
             },
             None),

            ("Leading space".into(),
             join(quote(bobl.iter(), " "), "\n"),
             None),

            ("Leading space, ends trimmed".into(),
             join(quote(bobl.iter(), " ").map(|l| l.trim_end().to_string()),
                  "\n"),
             None),

            ("Trailing space".into(),
             join(bobl.iter(), " \n"),
             None),

            ("Double spaced".into(),
             join(bobl.iter(), "\n\n"),
             None),

            ("Newlines replaced by spaces".into(),
             bobs.replace("\n", " ").into_bytes().into(),
             None),

            ("Quoted with '> '".into(),
             join(quote(bobl.iter(), "> "), "\n"),
             None),

            ("Quoted with '> ', ends trimmed".into(),
             join(quote(bobl.iter(), "> ").map(|l| l.trim_end().to_string()),
                  "\n"),
             None),

            ("Quoted with '] } >>> '".into(),
             join(quote(bobl.iter(), "] } >>> "), "\n"),
             None),

            ("Missing '-' in header".into(),
             bobs.clone().replacen("-", "", 1).into_bytes().into(),
             None),

            ("Unicode hyphens '‐'".into(),
             bobs.clone().replace("-", "‐").into_bytes().into(),
             None),

            ("No hyphens".into(),
             bobs.clone().replace("-", "").into_bytes().into(),
             None),

            ("Quoted-printable '=' -> '=3D'".into(),
             bobs.clone().replace("=", "=3D").into_bytes().into(),
             None),

            ("Dash-escaped frames".into(),
             bobs.clone().replace("-----B", "- -----B")
                         .replace("-----E", "- -----E").into_bytes().into(),
             None),

            ("Missing header".into(),
             {
                 let mut l = bobl.clone();
                 l.remove(0);
                 join(l.iter(), "\n")
             },
             None),

            ("Missing blank line".into(),
             {
                 let mut l = bobl.clone();
                 l.remove(2);
                 join(l.iter(), "\n")
             },
             None),

            ("Missing footer".into(),
             {
                 let mut l = bobl.clone();
                 l.remove(bobl.len() - 1);
                 join(l.iter(), "\n")
             },
             None),

            ("Bare base64 body".into(),
             {
                 let mut l = bobl.clone();
                 l.remove(bobl.len() - 1); // Footer.
                 l.remove(bobl.len() - 2); // Checksum.
                 l.remove(0); // Header.
                 l.remove(0); // Comment.
                 l.remove(0); // Separator.
                 join(l.iter(), "\n")
             },
             None),

            ("Bad checksum".into(),
             {
                 let mut l = bobl.clone();
                 l[bobl.len() - 2] = "=AAAA".into();
                 join(l.iter(), "\n")
             },
             None),
        ])
    }

    fn consume(&self, _i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        use sequoia_openpgp::{Cert, parse::Parse};
        let bob_fp =
            Cert::from_bytes(data::certificate("bob.pgp")).unwrap()
            .fingerprint();
        let ciphertext = pgp.encrypt_with_fp(artifact, bob_fp, self.message())
            .context("Encryption failed")?;
        pgp.new_context()?
            .decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
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
