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
        Test,
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
        "Hello World :)".as_bytes()
    }

    fn signature(&self) -> Result<Vec<u8>> {
        // Sign with Bob's subkey.
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

impl Test for ConcatenatedArmorKeyring {
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
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
