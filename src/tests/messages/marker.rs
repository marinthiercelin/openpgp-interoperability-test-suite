use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        P,
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests support for the Marker Packet.
pub struct MarkerPacket {
}

impl MarkerPacket {
    pub fn new() -> Result<MarkerPacket> {
        Ok(MarkerPacket {
        })
    }
}

impl Test for MarkerPacket {
    fn title(&self) -> String {
        "Marker Packet".into()
    }

    fn description(&self) -> String {
        "Tests whether the Marker Packet is correctly ignored."
            .into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MarkerPacket {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let marker = openpgp::Packet::Marker(Default::default());

        fn make<B: AsRef<[u8]>>(test: &str, b: B, kind: armor::Kind)
                                -> Result<(String, Data, Option<Expectation>)>
        {
            let mut buf = Vec::new();
            {
                let mut w = armor::Writer::new(&mut buf, kind)?;
                w.write_all(b.as_ref())?;
                w.finalize()?;
            }
            Ok((test.into(), buf.into(),
                Some(Ok("Marker packets MUST be ignored.".into()))))
        }

        Ok(vec![{
            let test = "Marker + Detached signature";
            let mut b = Vec::new();
            marker.serialize(&mut b)?;
            {
                let signer =
                    cert.keys().with_policy(P, None)
                    .for_signing().secret()
                    .nth(0).unwrap().key().clone()
                    .into_keypair().unwrap();
                let mut stack = Message::new(&mut b);
                stack = Signer::new(stack, signer).detached().build()?;
                stack.write_all(test.as_bytes())?;
                stack.finalize()?;
            }
            make(test, b, armor::Kind::Signature)?
        }, {
        // XXX: We cannot test signed messages.
        //    let test = "Marker + Signed Message";
        //    let mut b = Vec::new();
        //    marker.serialize(&mut b)?;
        //    {
        //        let signer =
        //            cert.keys().with_policy(P, None)
        //            .for_signing().secret()
        //            .nth(0).unwrap().key().clone()
        //            .into_keypair().unwrap();
        //        let mut stack = Message::new(&mut b);
        //        stack = Signer::new(stack, signer).build()?;
        //        stack = LiteralWriter::new(stack).build()?;
        //        stack.write_all(test.as_bytes())?;
        //        stack.finalize()?;
        //    }
        //    make(test, b, armor::Kind::Message)?
        //}, {
            let test = "Marker + Encrypted Message";
            let r: Recipient =
                cert.keys().with_policy(P, None)
                .for_transport_encryption()
                .nth(0).unwrap().key().into();
            let signer =
                cert.keys().with_policy(P, None)
                .for_signing().secret()
                .nth(0).unwrap().key().clone()
                .into_keypair().unwrap();
            let mut b = Vec::new();
            marker.serialize(&mut b)?;
            {
                let mut stack = Message::new(&mut b);
                stack = Encryptor::for_recipients(stack, vec![r]).build()?;
                stack = Signer::new(stack, signer).build()?;
                stack = LiteralWriter::new(stack).build()?;
                stack.write_all(test.as_bytes())?;
                stack.finalize()?;
            }
            make(test, b, armor::Kind::Message)?
        }, {
            let test = "Marker + Certificate";
            let mut b = Vec::new();
            marker.serialize(&mut b)?;
            cert.serialize(&mut b)?;
            make(test, b, armor::Kind::PublicKey)?
        }])
    }

    fn consume(&self, _i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        // Peek at the data to decide what to do.
        let pp = openpgp::PacketPile::from_bytes(artifact)?;
        let mut children = pp.children();

        match children.nth(1) {
            Some(openpgp::Packet::Signature(_)) => {
                // Detached signature.
                let test = b"Marker + Detached signature";
                pgp.verify_detached(data::certificate("bob.pgp"),
                                    test, artifact)
            },
            Some(openpgp::Packet::PublicKey(_)) => {
                // A certificate.
                let ciphertext =
                    pgp.encrypt(artifact, b"Marker + Certificate")?;
                pgp.decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
            },
            _ => {
                pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
            },
        }
    }
}
