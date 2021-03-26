use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    packet::Tag,
    parse::Parse,
    serialize::{
        Serialize,
        stream::*,
    },
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

/// Explores whether unknown signature packets are ignored when
/// verifying detached signatures.
pub struct UnknownPackets {
}

impl UnknownPackets {
    pub fn new() -> Result<UnknownPackets> {
        Ok(UnknownPackets {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for UnknownPackets {
    fn title(&self) -> String {
        "Detached signatures with unknown packets".into()
    }

    fn description(&self) -> String {
        "<p>This tests whether detached signatures with unknown \
        versions of Signature packets are still verified.  This \
        is important for the evolution of the message format.</p>"
            .into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }


    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for UnknownPackets {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary_key().key().clone();
        let primary_signer =
            primary.clone().parts_into_secret()?.into_keypair()?;

        let mut sig = Vec::new();
        {
            let message = Message::new(&mut sig);
            let mut signer = Signer::new(message, primary_signer)
                .detached()
                .build()?;
            signer.write_all(self.message())?;
            signer.finalize()?;
        }

        let sig4 = openpgp::PacketPile::from_bytes(&sig)?
            .into_children().collect::<Vec<_>>();
        assert_eq!(sig4.len(), 1);
        let sig4 = sig4[0].clone();
        assert_eq!(sig4.tag(), Tag::Signature);
        assert_eq!(sig4.kind(), Some(Tag::Signature));

        // Make a fictitious v23 signature.
        sig[3] = 23;
        let sig23 = openpgp::PacketPile::from_bytes(&sig)?
            .into_children().collect::<Vec<_>>();
        assert_eq!(sig23.len(), 1);
        let sig23 = sig23[0].clone();
        assert_eq!(sig23.tag(), Tag::Signature);
        assert_eq!(sig23.kind(), None);

        fn make_test(test: &str, packets: Vec<openpgp::Packet>,
                     expectation: Option<Expectation>)
                     -> Result<(String, Data, Option<Expectation>)> {
            use openpgp::armor;
            let mut w =
                armor::Writer::new(Vec::new(), armor::Kind::Signature)?;
            openpgp::PacketPile::from(packets).serialize(&mut w)?;
            let buf = w.finalize()?;
            Ok((test.into(), buf.into(), expectation))
        }

        Ok(vec![
            make_test("SIG4 SIG4",
                      vec![sig4.clone(), sig4.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4 SIG23",
                      vec![sig4.clone(), sig23.clone()],
                      Some(Ok("Unknown versions should be ignored".into())))?,
            make_test("SIG23 SIG4",
                      vec![sig23.clone(), sig4.clone()],
                      Some(Ok("Unknown versions should be ignored".into())))?,
        ])

    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(data::certificate("bob.pgp"), self.message(),
                            artifact)
    }
}
