use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::types::CompressionAlgorithm;
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for CompressionSupport {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::TPK::from_bytes(data::certificate("bob.pgp"))?;
        let mut t = Vec::new();

        use CompressionAlgorithm::*;
        for &c in &[Uncompressed, Zip, Zlib, BZip2] {
            let recipient: Recipient =
                cert.keys_all().encrypting_capable_for_transport()
                .nth(0).map(|(_, _, k)| k).unwrap().into();

            let mut b = Vec::new();

            {
                let stack = Message::new(&mut b);
                let stack =
                    Encryptor::for_recipient(stack, recipient).build()?;
                let stack = Compressor::new(stack).algo(c).build()?;
                let mut literal_writer = LiteralWriter::new(stack).build()?;

                write!(literal_writer, "Compressed using {}.", c)?;
            }

            t.push((c.to_string(), b.into_boxed_slice()));
        }

        Ok(t)
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Compression Algorithms");
    report.add(Box::new(CompressionSupport::new()?));
    Ok(())
}
