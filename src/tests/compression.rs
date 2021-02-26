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

/// Tests support for compression algorithms.
struct CompressionSupport {
}

impl CompressionSupport {
    pub fn new() -> Result<CompressionSupport> {
        Ok(CompressionSupport {
        })
    }
}

impl Test for CompressionSupport {
    fn title(&self) -> String {
        "Compression Algorithm support".into()
    }

    fn description(&self) -> String {
        "This tests support for the different compression algorithms \
         using Sequoia to generate the artifacts.".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for CompressionSupport {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;
        let mut t = Vec::new();

        use CompressionAlgorithm::*;
        for &c in &[Uncompressed, Zip, Zlib, BZip2] {
            let expectation = match c {
                Uncompressed =>
                    Some(Ok("Uncompressed MUST be supported.".into())),
                Zip =>
                    Some(Ok("SHOULD be able to decompress ZIP.".into())),
                Zlib =>
                    Some(Ok("Zlib SHOULD be supported.".into())),
                _ =>
                    None,
            };

            let recipient: Recipient =
                cert.keys().with_policy(super::P, None)
                .for_transport_encryption()
                .nth(0).unwrap().key().into();

            let mut b = Vec::new();

            {
                let stack = Message::new(&mut b);
                let stack =
                    Encryptor::for_recipients(stack, vec![recipient]).build()?;
                let stack = Compressor::new(stack).algo(c).build()?;
                let mut stack = LiteralWriter::new(stack).build()?;

                write!(stack, "Compressed using {}.", c)?;
                stack.finalize()?;
            }

            t.push((c.to_string(), b.into_boxed_slice(), expectation));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Compression Algorithms");
    plan.add(Box::new(CompressionSupport::new()?));
    Ok(())
}
