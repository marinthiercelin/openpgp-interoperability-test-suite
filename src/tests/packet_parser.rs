use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::Cert,
    packet::{Tag, header::*},
    parse::Parse,
    policy::StandardPolicy,
    serialize::Marshal,
    serialize::stream::*,
    types::CompressionAlgorithm,
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    plan::TestPlan,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

mod consumption;
use consumption::PacketConsumption;

/// Tests whether packet boundaries are enforced.
struct PacketBoundaries {
}

impl PacketBoundaries {
    pub fn new() -> Result<PacketBoundaries> {
        Ok(PacketBoundaries {
        })
    }

    fn make(&self, extend_by: u16) -> Result<Data> {
        let p = &StandardPolicy::new();
        let cert = Cert::from_bytes(data::certificate("bob.pgp"))?;
        let recipients = cert.keys()
            .with_policy(p, None)
            .alive()
            .revoked(false)
            .for_transport_encryption();

        let mut literal = Vec::new();
        {
            let mut message = LiteralWriter::new(Message::new(&mut literal))
                .build()?;
            message.write_all(b"If this decrypts fine, the implementation \
                                does not enforce packet boundaries")?;
            message.finalize()?;
        }

        let mut sink = Vec::new();
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message)
                .kind(openpgp::armor::Kind::Message)
                .build()?;
            let message = Encryptor::for_recipients(message, recipients)
                .build()?;
            let mut message =
                ArbitraryWriter::new(message, Tag::CompressedData)?;

            // Extend the message beyond the packet boundary.
            if literal[1] as u16 + extend_by < 192 {
                literal[1] += extend_by as u8;
            } else if literal[1] as u16 + extend_by < 8384 {
                let mut l = vec![literal[0]];
                BodyLength::Full(literal[1] as u32 + extend_by as u32)
                    .serialize(&mut l)?;
                l.extend_from_slice(&literal[2..]);
                literal = l;
            } else {
                unimplemented!("Cannot extend by {} bytes", extend_by);
            }
            let l = literal.len() as u16 + extend_by;
            message.write_all(&[
                CompressionAlgorithm::Zip.into(),
                0b0000_0001, // Final chunk, no compression
            ]).unwrap();
            // Length as little endian
            message.write_all(&l.to_le_bytes()).unwrap();
            // 1-complement of length as little endian
            message.write_all(&(!l).to_le_bytes()).unwrap();

            // Now the literal packet.
            message.write_all(&literal).unwrap();
            message.finalize().unwrap();
        }

        Ok(sink.into())
    }
}

impl Test for PacketBoundaries {
    fn title(&self) -> String {
        "Packet boundaries".into()
    }

    fn description(&self) -> String {
        "<p>Tests whether packet boundaries are properly enforced by \
        creating a compressed data packet where the compressed data \
        extends beyond the compressed data packet's boundaries.</p>"
            .into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Key".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for PacketBoundaries {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        Ok(vec![
            ("Base case".into(), self.make(0)?,
             Some(Ok("Base case".into()))),
            ("+1 byte".into(), self.make(1)?,
             Some(Err("Compressed data extends beyond packet".into()))),
            ("+4 bytes".into(), self.make(4)?,
             Some(Err("Compressed data extends beyond packet".into()))),
            ("+22 bytes".into(), self.make(22)?,
             Some(Err("Compressed data extends beyond packet".into()))),
            ("+23 bytes".into(), self.make(23)?,
             Some(Err("Compressed data extends beyond packet".into()))),
            ("+100 bytes".into(), self.make(100)?,
             Some(Err("Compressed data extends beyond packet".into()))),
            ("+8300 bytes".into(), self.make(8300)?,
             Some(Err("Compressed data extends beyond packet".into()))),
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Packet parser");
    plan.add(Box::new(PacketBoundaries::new()?));
    plan.add(Box::new(PacketConsumption::new()?));
    Ok(())
}
