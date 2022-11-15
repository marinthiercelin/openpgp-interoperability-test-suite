use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    parse::Parse,
    serialize::stream::*,
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        ConsumerTest,
        Expectation,
        TestMatrix,
    },
};

/// Explores whether concatenated ASCII Armor blocks are recognized as
/// keyring.
pub struct ConcatenatedArmorKeyring {
}

impl ConcatenatedArmorKeyring {
    pub fn new() -> Result<ConcatenatedArmorKeyring> {
        Ok(ConcatenatedArmorKeyring {
        })
    }

    fn message(&self) -> &'static [u8] {
        crate::tests::MESSAGE
    }

    fn signature(&self) -> Result<Vec<u8>> {
        // Sign with Bob's primary key.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let signing_keypair =
            cert.keys().nth(0).unwrap()
            .key().clone().parts_into_secret()?.into_keypair()?;

        let mut sig = Vec::new();
        let message = Message::new(&mut sig);
        let message = Armorer::new(message)
            .kind(armor::Kind::Signature)
            .build()?;
        let mut signer = Signer::new(message, signing_keypair)
            .detached()
            .build()?;
        signer.write_all(self.message())?;
        signer.finalize()?;
        Ok(sig)
    }
}

impl crate::plan::Runnable<TestMatrix> for ConcatenatedArmorKeyring {
    fn title(&self) -> String {
        "Concatenated ASCII Armor Keyring".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>Explores whether concatenated ASCII Armor blocks are \
           recognized as keyring.  This is not mandated by OpenPGP, \
           but some implementations may chose to support this.</p>\
           \
           <p>The signature is from Bob over the string <code>{}</code>.</p>",
          String::from_utf8(self.message().into()).unwrap())
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Signature".into(), self.signature().unwrap().into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for ConcatenatedArmorKeyring {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        const TEXT: &[u8] = b"TEXT\n";
        Ok(vec![
            ("[Bob]".into(),
             {
                 let v = data::certificate("bob.pgp").to_vec();
                 v.into()
             },
             Some(Ok("Base case".into()))),

            ("[Bob] [Alice]".into(),
             {
                 let mut v = data::certificate("bob.pgp").to_vec();
                 v.extend_from_slice(data::certificate("alice.pgp"));
                 v.into()
             },
             None),

            ("[Alice] [Bob]".into(),
             {
                 let mut v = data::certificate("alice.pgp").to_vec();
                 v.extend_from_slice(data::certificate("bob.pgp"));
                 v.into()
             },
             None),

            ("Text [Bob] Text [Alice] Text".into(),
             {
                 let mut v = TEXT.to_vec();
                 v.extend_from_slice(data::certificate("bob.pgp"));
                 v.extend_from_slice(TEXT);
                 v.extend_from_slice(data::certificate("alice.pgp"));
                 v.extend_from_slice(TEXT);
                 v.into()
             },
             None),

            ("Text [Alice] Text [Bob] Text".into(),
             {
                 let mut v = TEXT.to_vec();
                 v.extend_from_slice(data::certificate("alice.pgp"));
                 v.extend_from_slice(TEXT);
                 v.extend_from_slice(data::certificate("bob.pgp"));
                 v.extend_from_slice(TEXT);
                 v.into()
             },
             None),
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(artifact, self.message(), &self.signature()?)
    }
}

/// Explores whether concatenated ASCII Armor blocks are recognized as
/// a sequence of signatures.
pub struct ConcatenatedArmorSignatures {
}

impl ConcatenatedArmorSignatures {
    pub fn new() -> Result<ConcatenatedArmorSignatures> {
        Ok(ConcatenatedArmorSignatures {
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for ConcatenatedArmorSignatures {
    fn title(&self) -> String {
        "Concatenated ASCII Armor Signatures".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>Explores whether concatenated ASCII Armor blocks are \
           recognized as sequence of signatures.  This is not \
           mandated by OpenPGP, but some implementations may \
           chose to support this.</p> \
           \
           <p>The signatures are from Bob and Ricarda over the \
           string <code>{}</code>, but we only use Bob's cert to \
           verify the signatures.</p>",
          String::from_utf8(crate::tests::MESSAGE.into()).unwrap())
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![
            ("Bob's Cert".into(), data::certificate("bob.pgp").into()),
            ("Ricarda's Cert".into(), data::certificate("ricarda.pgp").into()),
        ]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for ConcatenatedArmorSignatures {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let make_sig = |cert| -> Result<Vec<u8>> {
            let cert = openpgp::Cert::from_bytes(cert)?;
            let signer =
                cert.with_policy(crate::tests::P, None)?
                .keys().secret().for_signing().next().unwrap()
                .key().clone().into_keypair()?;

            let mut buf = Vec::new();
            {
                let message = Message::new(&mut buf);
                let message = Armorer::new(message)
                    .kind(armor::Kind::Signature)
                    .build()?;
                let mut signer = Signer::new(message, signer)
                    .detached()
                    .build()?;
                signer.write_all(crate::tests::MESSAGE)?;
                signer.finalize()?;
            }
            Ok(buf)
        };

        let bob = make_sig(data::certificate("bob-secret.pgp"))?;
        let ricarda = make_sig(data::certificate("ricarda-secret.pgp"))?;

        const TEXT: &[u8] = b"TEXT\n";
        Ok(vec![
            ("[Bob]".into(),
             {
                 let v = bob.clone();
                 v.into()
             },
             Some(Ok("Base case".into()))),

            ("[Bob] [Ricarda]".into(),
             {
                 let mut v = bob.clone();
                 v.extend_from_slice(&ricarda);
                 v.into()
             },
             None),

            ("[Ricarda] [Bob]".into(),
             {
                 let mut v = ricarda.clone();
                 v.extend_from_slice(&bob);
                 v.into()
             },
             None),

            ("Text [Bob] Text [Ricarda] Text".into(),
             {
                 let mut v = TEXT.to_vec();
                 v.extend_from_slice(&bob);
                 v.extend_from_slice(TEXT);
                 v.extend_from_slice(&ricarda);
                 v.extend_from_slice(TEXT);
                 v.into()
             },
             None),

            ("Text [Ricarda] Text [Bob] Text".into(),
             {
                 let mut v = TEXT.to_vec();
                 v.extend_from_slice(&ricarda);
                 v.extend_from_slice(TEXT);
                 v.extend_from_slice(&bob);
                 v.extend_from_slice(TEXT);
                 v.into()
             },
             None),
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.sop()
            .verify()
            .cert(data::certificate("bob.pgp"))
            .signatures(artifact)
            .data_raw(crate::tests::MESSAGE)
    }
}
