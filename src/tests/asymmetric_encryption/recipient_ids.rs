use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    parse::Parse,
    types::SymmetricAlgorithm,
};
use crate::{
    OpenPGP,
    Data,
    Result,
    data,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests how recipient ids are handled.
pub struct RecipientIDs {
}

impl RecipientIDs {
    pub fn new() -> Result<RecipientIDs> {
        Ok(RecipientIDs {
        })
    }
}

impl Test for RecipientIDs {
    fn title(&self) -> String {
        "Recipient IDs".into()
    }

    fn description(&self) -> String {
        "<p>Tests variations of recipient ids.</p>".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("TSK".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for RecipientIDs {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        // The tests.
        let mut t = Vec::new();

        // Use the RSA key to increase compatibility.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;

        // The base case.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message).build()?;
        let recipients =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption();
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(crate::tests::MESSAGE)?;
        message.finalize()?;
        t.push(("Encryption subkey's KeyID".into(),
                buf.into(),
                Some(Ok("Base case".into()))));

        // Wildcard.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message).build()?;
        let recipients =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .map(|key| Recipient::from(key)
                 .set_keyid(openpgp::KeyID::wildcard()));
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(crate::tests::MESSAGE)?;
        message.finalize()?;
        t.push(("Wildcard KeyID".into(),
                buf.into(),
                Some(Ok("Interoperability concern".into()))));

        // Certificate.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message).build()?;
        let recipients =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .map(|key| Recipient::from(key)
                 .set_keyid(cert.keyid()));
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(crate::tests::MESSAGE)?;
        message.finalize()?;
        t.push(("Certificate KeyID".into(),
                buf.into(),
                None));

        // Fictitious encrypted keyid.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message).build()?;
        let recipients =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .map(|key| Recipient::from(key)
                 .set_keyid("AAAA BBBB CCCC DDDD".parse().unwrap()));
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(crate::tests::MESSAGE)?;
        message.finalize()?;
        t.push(("Fictitious KeyID".into(),
                buf.into(),
                None));

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == crate::tests::MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                crate::tests::MESSAGE, artifact))
        }
    }

}
