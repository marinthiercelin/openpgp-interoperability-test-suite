use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::types::CompressionAlgorithm;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

mod unknown_packets;

/// Tests various conforming, but unusual message structures.
struct MessageStructure {
}

impl MessageStructure {
    pub fn new() -> Result<MessageStructure> {
        Ok(MessageStructure {
        })
    }
}

impl Test for MessageStructure {
    fn title(&self) -> String {
        "Unusual Message Structure".into()
    }

    fn description(&self) -> String {
        "This test generates valid messages with an unusual structure."
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

impl ConsumerTest for MessageStructure {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;
        use CompressionAlgorithm::Zip;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let mut t = Vec::new();

        for &structure in &[
            "ecs", // Base case, Sign-then-compress-then-encrypt.
            "esc",
            "ces",
            "cse",
            "sec",
            "sce",
            "ees",
            "ese",
            "ses",
            "ecc",
            "ees",
            "ess",
            "esss",
        ] {
            let mut layers = Vec::new();
            let mut test;

            let mut b = Vec::new();
            {
                let mut stack = Message::new(&mut b);

                for layer in structure.chars() {
                    match layer {
                        'e' => {
                            let r: Recipient =
                                cert.keys().with_policy(super::P, None)
                                .for_transport_encryption()
                                .nth(0).unwrap().key().into();
                            stack =
                                Encryptor::for_recipients(stack, vec![r])
                                .build()?;
                            layers.push("encrypt");
                        },
                        'c' => {
                            stack =
                                Compressor::new(stack).algo(Zip).build()?;
                            layers.push("compress");
                        },
                        's' => {
                            let signer =
                                cert.keys().with_policy(super::P, None).for_signing().secret()
                                .nth(0).unwrap().key().clone()
                                .into_keypair().unwrap();
                            stack =
                                Signer::new(stack, signer).build()?;
                            layers.push("sign");
                        },
                        _ => unreachable!("invalid layer code"),
                    }
                }
                stack = LiteralWriter::new(stack).build()?;
                test = layers.join(" ∘ ");
                stack.write_all(test.as_bytes())?;
                stack.finalize()?;
            }
            t.push((test, b.into_boxed_slice(), None));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

/// Tests maximum recursion depth of the consumer's parser.
struct RecursionDepth {
    max: u32,
}

impl RecursionDepth {
    pub fn new(max: u32) -> Result<RecursionDepth> {
        Ok(RecursionDepth {
            max,
        })
    }
}

impl Test for RecursionDepth {
    fn title(&self) -> String {
        "Maximum recursion depth".into()
    }

    fn description(&self) -> String {
        "This test encrypts messages, with the plaintext being compressed \
         N times to evaluate the maximum recursion depth of implementations."
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

impl ConsumerTest for RecursionDepth {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;
        let mut t = Vec::new();

        for n in (0..self.max).map(|n| 2_usize.pow(n)) {
            let mut b = Vec::new();

            let expectation = if n < 8 {
                Some(Ok("Maximum recursion depth too small".into()))
            } else if n > 16 {
                Some(Err("Maximum recursion depth too large".into()))
            } else {
                None
            };

            {
                let r: Recipient =
                    cert.keys().with_policy(super::P, None).for_transport_encryption()
                    .nth(0).unwrap().key().into();

                let stack = Message::new(&mut b);
                let mut stack =
                    Encryptor::for_recipients(stack, vec![r]).build()?;

                for _ in 0..(n - 1) {
                    stack = Compressor::new(stack)
                        .algo(CompressionAlgorithm::Zip).build()?;
                }

                let mut stack = LiteralWriter::new(stack).build()?;
                write!(stack, "Literal data at depth {}.", n)?;
                stack.finalize()?;
            }

            t.push((format!("Depth {}", n), b.into_boxed_slice(), expectation));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

/// Tests support for the Marker Packet.
struct MarkerPacket {
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
            let test = "Marker + Signed Message";
            let mut b = Vec::new();
            marker.serialize(&mut b)?;
            {
                let signer =
                    cert.keys().with_policy(super::P, None)
                    .for_signing().secret()
                    .nth(0).unwrap().key().clone()
                    .into_keypair().unwrap();
                let mut stack = Message::new(&mut b);
                stack = Signer::new(stack, signer).build()?;
                stack = LiteralWriter::new(stack).build()?;
                stack.write_all(test.as_bytes())?;
                stack.finalize()?;
            }
            make(test, b, armor::Kind::Message)?
        }, {
            let test = "Marker + Encrypted Message";
            let r: Recipient =
                cert.keys().with_policy(super::P, None)
                .for_transport_encryption()
                .nth(0).unwrap().key().into();
            let signer =
                cert.keys().with_policy(super::P, None)
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

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        // Peek at the data to decide what to do.
        let pp = openpgp::PacketPile::from_bytes(artifact)?;
        let mut children = pp.children();
        if let Some(openpgp::Packet::PublicKey(_)) = children.nth(1) {
            // A certificate.
            let ciphertext = pgp.encrypt(artifact, b"Marker + Certificate")?;
            pgp.decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
        } else {
            pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
        }
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Message structure");
    report.add(Box::new(MessageStructure::new()?));
    report.add(Box::new(RecursionDepth::new(7)?));
    report.add(Box::new(MarkerPacket::new()?));
    report.add(Box::new(unknown_packets::UnknownPackets::new()?));
    Ok(())
}
