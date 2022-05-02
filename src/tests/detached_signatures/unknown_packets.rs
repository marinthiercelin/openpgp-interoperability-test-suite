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
        vec![
            ("Bob's certificate".into(), data::certificate("bob.pgp").into()),
            ("Ricarda's certificate".into(), data::certificate("ricarda.pgp").into()),
        ]
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

        let cert_ricarda =
            openpgp::Cert::from_bytes(data::certificate("ricarda-secret.pgp"))?;
        let ricarda_signer =
            cert_ricarda.with_policy(crate::tests::P, None)?
            .keys().secret().for_signing().next().unwrap()
            .key().clone().into_keypair()?;

        let mut sig = Vec::new();
        {
            let message = Message::new(&mut sig);
            let mut signer = Signer::new(message, primary_signer)
                .add_signer(ricarda_signer)
                .detached()
                .build()?;
            signer.write_all(crate::tests::MESSAGE)?;
            signer.finalize()?;
        }

        let pp = openpgp::PacketPile::from_bytes(&sig)?
            .into_children().collect::<Vec<_>>();
        assert_eq!(pp.len(), 2);
        let sig4 = pp[0].clone();
        assert_eq!(sig4.tag(), Tag::Signature);
        assert_eq!(sig4.kind(), Some(Tag::Signature));
        let sig4_r = pp[1].clone();
        assert_eq!(sig4_r.tag(), Tag::Signature);
        assert_eq!(sig4_r.kind(), Some(Tag::Signature));

        // Make a fictitious v23 signature.
        sig[3] = 23;
        let pp = openpgp::PacketPile::from_bytes(&sig)?
            .into_children().collect::<Vec<_>>();
        assert_eq!(pp.len(), 2);
        let sig23 = pp[0].clone();
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
            make_test("SIG4_bob",
                      vec![sig4.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4_ricarda",
                      vec![sig4_r.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4_b SIG4_r, use Bob's cert",
                      vec![sig4.clone(), sig4_r.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4_b SIG4_r, use Ricarda's cert",
                      vec![sig4.clone(), sig4_r.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4_r SIG4_b, use Bob's cert",
                      vec![sig4_r.clone(), sig4.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4_r SIG4_b, use Ricarda's cert",
                      vec![sig4_r.clone(), sig4.clone()],
                      Some(Ok("Base case".into())))?,
            make_test("SIG4 SIG23",
                      vec![sig4.clone(), sig23.clone()],
                      Some(Ok("Unknown versions should be ignored".into())))?,
            make_test("SIG23 SIG4",
                      vec![sig23.clone(), sig4.clone()],
                      Some(Ok("Unknown versions should be ignored".into())))?,
        ])

    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let verify_with_cert = match i {
            0..=5 => if i % 2 == 0 {
                data::certificate("bob.pgp")
            } else {
                data::certificate("ricarda.pgp")
            },
            _ => data::certificate("bob.pgp"),
        };

        pgp.sop()
            .verify()
            .cert(verify_with_cert)
            .signatures(artifact)
            .data_raw(crate::tests::MESSAGE)
    }
}
