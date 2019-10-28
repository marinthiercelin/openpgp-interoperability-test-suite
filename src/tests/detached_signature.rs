use failure::ResultExt;

use sequoia_openpgp as openpgp;
use openpgp::constants::HashAlgorithm;
use openpgp::parse::Parse;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        Test,
        ProducerConsumerTest,
    },
};

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub struct DetachedSignVerifyRoundtrip {
    title: String,
    description: String,
    cert: openpgp::TPK,
    hash: Option<HashAlgorithm>,
    message: Data,
}

impl DetachedSignVerifyRoundtrip {
    pub fn new(title: &str, description: &str, cert: openpgp::TPK,
               message: Data) -> DetachedSignVerifyRoundtrip {
        DetachedSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            hash: None,
            message,
        }
    }

    pub fn with_hash(title: &str, description: &str, cert: openpgp::TPK,
                     message: Data,
                     hash: HashAlgorithm)
                     -> Result<DetachedSignVerifyRoundtrip>
    {
        // Change the hash algorithm preferences of CERT.
        let (uidb, sig, _) = cert.primary_userid_full(None).unwrap();
        let builder = openpgp::packet::signature::Builder::from(sig.clone())
            .set_preferred_hash_algorithms(vec![hash])?;
        let mut primary_keypair =
            cert.primary().clone().mark_parts_secret().into_keypair()?;
        let new_sig = uidb.userid().bind(
            &mut primary_keypair,
            &cert, builder, None, None)?;
        let cert = cert.merge_packets(vec![new_sig.into()])?;

        Ok(DetachedSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            hash: Some(hash),
            message,
        })
    }
}

impl Test for DetachedSignVerifyRoundtrip {
    fn title(&self) -> String {
        self.title.clone()
    }

    fn description(&self) -> String {
        self.description.clone()
    }
}

impl ProducerConsumerTest for DetachedSignVerifyRoundtrip {
    fn produce(&self, pgp: &mut OpenPGP)
               -> Result<Data> {
        pgp.sign_detached(&self.cert, &self.message)
    }

    fn check_producer(&self, artifact: &[u8]) -> Result<()> {
        let pp = openpgp::PacketPile::from_bytes(&artifact)
            .context("Produced data is malformed")?;
        if pp.children().count() != 1 {
            return Err(failure::format_err!(
                "Producer produced more than one packet: {:?}",
                pp.children().collect::<Vec<_>>()));
        }

        match pp.children().next().unwrap() {
            openpgp::Packet::Signature(p) =>
                if let Some(hash) = self.hash {
                    if p.hash_algo() != hash {
                        return Err(failure::format_err!(
                            "Producer did not use {:?}, but {:?}",
                            hash, p.hash_algo()));
                    }
                },

            p => return
                Err(failure::format_err!(
                    "Producer did produce an Signature packet, found \
                     {:?} packet", p)),
        }

        Ok(())
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(&self.cert, &self.message, &artifact)
    }
}

pub fn run(report: &mut Report, implementations: &[Box<dyn OpenPGP>])
           -> Result<()> {
    report.add_section("Detached Signatures")?;
    report.add(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Alice'",
            "Detached Sign-Verify roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("alice-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())
            .run(implementations)?)?;
    report.add(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Bob'",
            "Detached Sign-Verify roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())
            .run(implementations)?)?;
    Ok(())
}
