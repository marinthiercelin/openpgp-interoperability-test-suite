use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::types::CompressionAlgorithm;
use openpgp::parse::Parse;

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

mod signed;
mod unknown_packets;
mod marker;
mod trust;
mod malformed;

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

    fn run(&self, implementations: &[crate::Sop])
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
            "ess",
            "esss",
        ] {
            let mut layers = Vec::new();
            let test;

            let mut b = Vec::new();
            {
                let stack = Message::new(&mut b);
                let mut stack = Armorer::new(stack).build()?;

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
            t.push((test, b.into(), None));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
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

    fn run(&self, implementations: &[crate::Sop])
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
                let stack = Armorer::new(stack).build()?;
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

            t.push((format!("Depth {}", n), b.into(), expectation));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Message structure");
    plan.add(Box::new(MessageStructure::new()?));
    plan.add(Box::new(RecursionDepth::new(7)?));
    plan.add(Box::new(signed::Signed::new()?));
    plan.add(Box::new(marker::MarkerPacket::new()?));
    plan.add(Box::new(trust::TrustPacket::new()?));
    plan.add(Box::new(unknown_packets::UnknownPackets::new()?));
    plan.add(Box::new(malformed::Malformed::new()?));
    Ok(())
}
