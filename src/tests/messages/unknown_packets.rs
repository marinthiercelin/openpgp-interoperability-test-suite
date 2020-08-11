use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    PacketPile,
    crypto::S2K,
    packet::prelude::*,
    parse::Parse,
    serialize::{Serialize, MarshalInto},
    types::{HashAlgorithm, SymmetricAlgorithm},
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

/// Tests support for messages containing unknown packets.
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
        "Messages with unknown packets".into()
    }

    fn description(&self) -> String {
        "<p>This tests whether encrypted messages with unknown \
        versions of PKESK and SKESK packets are still decrypted.  This \
        is important for the evolution of the message format.</p>"
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

impl ConsumerTest for UnknownPackets {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        // The tests.
        let mut t = Vec::new();
        // Makes tests.
        let make =
            |test: &str, packets: Vec<&Packet>, expectation: Option<Expectation>|
            -> Result<(String, Data, Option<Expectation>)>
        {
            let mut buf = Vec::new();
            {
                use openpgp::armor;
                let mut w =
                    armor::Writer::new(&mut buf, armor::Kind::Message)?;
                for p in packets {
                    p.serialize(&mut w)?;
                }
                w.finalize()?;
            }
            Ok((test.into(), buf.into(), expectation))
        };

        // Use the RSA key to increase compatibility.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;
        let recipient: Recipient =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .nth(0).unwrap().key().into();

        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Encryptor::for_recipients(message, vec![recipient])
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(b"Encrypted using SEIP + MDC.")?;
        message.finalize()?;

        let packets =
            PacketPile::from_bytes(&buf)?.into_children().collect::<Vec<_>>();
        assert_eq!(packets.len(), 2);
        let pkesk = &packets[0];
        let seip = &packets[1];

        // The base case as-is.
        t.push(make("Base case",
                    vec![pkesk, seip],
                    Some(Ok("SEIP is a MUST according to RFC4880.".into())))?);

        // Insert an as-of-yet unknown version of a PKESK packet.
        let mut unknown = Unknown::new(
            Tag::PKESK, openpgp::Error::MalformedPacket("".into()).into());
        // Create a made-up future PKESK packet mimicking the v3 one.
        unknown.set_body(vec![
            // Version
            23,
            // Easily recognized "recipient id"
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            // Cihper
            SymmetricAlgorithm::AES256.into(),
            // ESK
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        ]);
        let unknown = Packet::from(unknown);
        t.push(make("PKESK3 PKESK23 SEIP",
                    vec![pkesk, &unknown, seip],
                    Some(Ok("Unknown versions should be ignored".into())))?);
        t.push(make("PKESK23 PKESK3 SEIP",
                    vec![&unknown, pkesk, seip],
                    Some(Ok("Unknown versions should be ignored".into())))?);

        // Insert an as-of-yet unknown version of a SKESK packet.
        let mut unknown = Unknown::new(
            Tag::SKESK, openpgp::Error::MalformedPacket("".into()).into());
        // Create a made-up future SKESK packet mimicking the v4 one.
        let mut body = vec![
            // Version
            23,
            // Cihper
            SymmetricAlgorithm::AES256.into(),
        ];
        // Add a S2K object.
        body.extend_from_slice(&S2K::default().to_vec()?);
        // ESK
        body.extend_from_slice(&[
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        ]);
        unknown.set_body(body);
        let unknown = Packet::from(unknown);
        t.push(make("PKESK3 SKESK23 SEIP",
                    vec![pkesk, &unknown, seip],
                    Some(Ok("Unknown versions should be ignored".into())))?);
        t.push(make("SKESK23 PKESK3 SEIP",
                    vec![&unknown, pkesk, seip],
                    Some(Ok("Unknown versions should be ignored".into())))?);

        // Insert an SKESK4 object with an as-of-yet unknown S2K parameters.
        let mut unknown = Unknown::new(
            Tag::SKESK, openpgp::Error::MalformedPacket("".into()).into());
        // Create a made-up future SKESK packet mimicking the v4 one.
        let body = vec![
            // Version
            4,
            // Cihper
            SymmetricAlgorithm::AES256.into(),
            // Add an unknown S2K object.
            23, // Version
            HashAlgorithm::SHA256.into(), // Hash
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, // Salt
            0x41, 0x41, 0x41, 0x41, // Additional parameters
            // ESK
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        ];
        unknown.set_body(body);
        let unknown = Packet::from(unknown);
        t.push(make("PKESK3 SKESK4+S2K23 SEIP",
                    vec![pkesk, &unknown, seip],
                    Some(Ok("Unknown versions should be ignored".into())))?);
        t.push(make("SKESK4+S2K23 PKESK3 SEIP",
                    vec![&unknown, pkesk, seip],
                    Some(Ok("Unknown versions should be ignored".into())))?);

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}
