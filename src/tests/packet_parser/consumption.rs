use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::Cert,
    parse::Parse,
    policy::StandardPolicy,
    serialize::stream::{*, padding::*},
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests whether excess bytes in a packet are correctly consumed.
pub struct PacketConsumption {
}

impl PacketConsumption {
    pub fn new() -> Result<PacketConsumption> {
        Ok(PacketConsumption {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }

    fn make(&self, policy: fn(u64) -> u64) -> Result<Data> {
        let p = &StandardPolicy::new();
        let cert = Cert::from_bytes(data::certificate("bob.pgp"))?;
        let recipients = cert.keys()
            .with_policy(p, None)
            .alive()
            .revoked(false)
            .for_transport_encryption();

        let mut sink = Vec::new();
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message)
                .kind(openpgp::armor::Kind::Message)
                .build()?;
            let message = Encryptor::for_recipients(message, recipients)
                .build()?;
            let message = Padder::new(message)
                .with_policy(policy)
                .build()?;
            let mut message = LiteralWriter::new(message)
                .build()?;
            message.write_all(self.message())?;
            message.finalize()?;
        }

        Ok(sink.into())
    }
}

impl Test for PacketConsumption {
    fn title(&self) -> String {
        "Packet excess consumption".into()
    }

    fn description(&self) -> String {
        format!(
            "<p>Tests whether excess bytes in a packet are correctly
            consumed.  The compressed data packet presents the unique
            opportunity to test whether the packet parser actually
            consumes (i.e. advances the read cursor) all the bytes
            specified in a packet header, even though they are not
            consumed by the underlying decompression
            algorithm.</p>\
            \
            <p>The plaintext message is the string <code>{}</code>,
            padded by the specified number of bytes using excess data
            in the compression stream.</p>",
            String::from_utf8(self.message().into()).unwrap())
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Key".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for PacketConsumption {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        Ok(vec![
            ("Base case".into(), self.make(|n| n)?,
             Some(Ok("Base case".into()))),
            ("+1 byte".into(), self.make(|n| n + 1)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+10 bytes".into(), self.make(|n| n + 10)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+100 bytes".into(), self.make(|n| n + 100)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+1_000 bytes".into(), self.make(|n| n + 1_000)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+10_000 bytes".into(), self.make(|n| n + 10_000)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+100_000 bytes".into(), self.make(|n| n + 100_000)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+1_000_000 bytes".into(), self.make(|n| n + 1_000_000)?,
             Some(Ok("Excess data must be discarded".into()))),
            ("+10_000_000 bytes".into(), self.make(|n| n + 10_000_000)?,
             Some(Ok("Excess data must be discarded".into()))),
        ])
    }

    fn consume(&self, _i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == self.message() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                self.message(), artifact))
        }
    }
}
