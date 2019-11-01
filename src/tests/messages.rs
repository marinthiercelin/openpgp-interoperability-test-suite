use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::constants::{CompressionAlgorithm, KeyFlags};
use openpgp::parse::Parse;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MessageStructure {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        use openpgp::serialize::stream::*;
        use CompressionAlgorithm::Zip;

        let cert =
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?;
        let mode = KeyFlags::default()
            .set_encrypt_at_rest(true).set_encrypt_for_transport(true);
        let r: Recipient =
            cert.keys_all().key_flags(mode)
            .nth(0).map(|(_, _, k)| k).unwrap().into();
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
        ] {
            let mut layers = Vec::new();
            let mut test;

            let mut b = Vec::new();
            {
                let mut stack = Message::new(&mut b);

                for layer in structure.chars() {
                    match layer {
                        'e' => {
                            stack =
                                Encryptor::new(stack, &[], vec![&r], None,
                                               None)?;
                            layers.push("encrypt");
                        },
                        'c' => {
                            stack =
                                Compressor::new(stack, Zip, None)?;
                            layers.push("compress");
                        },
                        's' => {
                            // XXX: Due to the design of Signer, we
                            // currently have to leak the signing
                            // keypair here.
                            let signer = Box::new(
                                cert.keys_all().signing_capable().secret(true)
                                .nth(0).map(|(_, _, k)| k).unwrap().clone()
                                .mark_parts_secret().into_keypair().unwrap());
                            stack =
                                Signer::new(stack, vec![Box::leak(signer)],
                                            None)?;
                            layers.push("sign");
                        },
                        _ => unreachable!("invalid layer code"),
                    }
                }
                stack = LiteralWriter::new(stack, None, None, None)?;
                test = layers.join(" ∘ ");
                stack.write_all(test.as_bytes())?;
                stack.finalize()?;
            }
            t.push((test, b.into_boxed_slice()));
        }

        Ok(t)
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for RecursionDepth {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::TPK::from_bytes(data::certificate("bob.pgp"))?;
        let mode = KeyFlags::default()
            .set_encrypt_at_rest(true).set_encrypt_for_transport(true);
        let r: Recipient =
            cert.keys_all().key_flags(mode)
            .nth(0).map(|(_, _, k)| k).unwrap().into();
        let mut t = Vec::new();

        for n in (0..self.max).map(|n| 2_usize.pow(n)) {
            let mut b = Vec::new();

            {
                let stack = Message::new(&mut b);
                let mut stack =
                    Encryptor::new(stack, &[], vec![&r], None, None)?;

                for _ in 0..(n - 1) {
                    stack = Compressor::new(
                        stack, CompressionAlgorithm::Zip, None)?;
                }

                let mut stack = LiteralWriter::new(stack, None, None, None)?;
                write!(stack, "Literal data at depth {}.", n)?;
                stack.finalize()?;
            }

            t.push((format!("Depth {}", n), b.into_boxed_slice()));
        }

        Ok(t)
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Message structure");
    report.add(Box::new(MessageStructure::new()?));
    report.add(Box::new(RecursionDepth::new(7)?));
    Ok(())
}
