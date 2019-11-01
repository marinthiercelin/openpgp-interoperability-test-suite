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

/// Tests maximum recursion depth of the consumer's parser.
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
        "This test support for the different compression algorithms.".into()
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
        let mode = KeyFlags::default()
            .set_encrypt_at_rest(true).set_encrypt_for_transport(true);
        let recipient: Recipient =
            cert.keys_all().key_flags(mode)
            .nth(0).map(|(_, _, k)| k).unwrap().into();
        let mut t = Vec::new();

        use CompressionAlgorithm::*;
        for &c in &[Uncompressed, Zip, Zlib, BZip2] {
            let mut b = Vec::new();

            {
                let stack = Message::new(&mut b);
                let stack =
                    Encryptor::new(stack, &[], vec![&recipient], None, None)?;
                let stack = Compressor::new(stack, c, None)?;

                let mut literal_writer =
                    LiteralWriter::new(stack, None, None, None)?;

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
