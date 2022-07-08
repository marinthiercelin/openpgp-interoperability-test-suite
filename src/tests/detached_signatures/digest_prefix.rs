use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    PacketPile,
    crypto::hash::{Hash, Digest},
    packet::{Any, Signature},
    parse::Parse,
    serialize::{
        MarshalInto,
        stream::*,
    },
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        ConsumerTest,
        Expectation,
        TestMatrix,
    },
};

fn corrupt_hash_digest(p: Packet) -> Result<Packet> {
    if let Packet::Signature(sig) = &p {
        let mut buf = p.to_vec()?;
        let buf_len = buf.len();
        let mpi_len = sig.mpis().serialized_len();
        buf[buf_len - mpi_len - 2] = 0;
        buf[buf_len - mpi_len - 1] = 0;
        Packet::from_bytes(&buf)
    } else {
        Ok(p)
    }
}

/// Explores whether implementations set the digest prefix correctly,
/// and whether they consider signatures with invalid digest prefixes
/// invalid.
pub struct DigestPrefix {
    bob_corrupted: Data,
}

impl DigestPrefix {
    pub fn new() -> Result<DigestPrefix> {
        let bob_corrupted =
            PacketPile::from_bytes(data::certificate("bob.pgp"))?
            .into_children()
            .map(|p| corrupt_hash_digest(p).unwrap())
            .collect::<PacketPile>()
            .to_vec()?
            .into();
        Ok(DigestPrefix {
            bob_corrupted,
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for DigestPrefix {
    fn title(&self) -> String {
        "Signature digest prefix".into()
    }

    fn description(&self) -> String {
        "<p>Explores whether implementations set the digest prefix correctly, \
         and whether they consider signatures with invalid digest prefixes \
         invalid.  There are three checks:</p>\
         <ol><li>We ask implementations to make a detached signature and check \
         whether the digest prefix is correct.</li>\
         <li>We make a detached signature, corrupt the digest prefix, and ask \
         implementations to verify it.</li>\
         <li>We ask implementations to verify a signature using a cert where \
         we corrupted all digest prefixes in the binding signatures.</li></ol>"
            .into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![
            ("Bob's key".into(), data::certificate("bob-secret.pgp").into()),
            ("Bob's cert".into(), data::certificate("bob.pgp").into()),
            ("Bob's cert with corrupted digest prefixes".into(),
             self.bob_corrupted.clone()),
        ]
    }


    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for DigestPrefix {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary_key().key().clone();
        let primary_signer =
            primary.clone().parts_into_secret()?.into_keypair()?;

        let mut sig = Vec::new();
        let message = Message::new(&mut sig);
        let mut signer = Signer::new(message, primary_signer)
            .detached()
            .build()?;
        signer.write_all(crate::tests::MESSAGE)?;
        signer.finalize()?;
        let sig = Packet::from_bytes(&sig)?;

        Ok(vec![
            ("Checking produced prefix".into(),
             data::certificate("bob-secret.pgp").into(),
             Some(Ok("Digest prefix MUST be set correctly".into()))),
            ("Sig w/corrupted prefix".into(),
             corrupt_hash_digest(sig.clone())?.to_vec()?.into(),
             None),
            ("Cert w/corrupted prefixes".into(),
             sig.to_vec()?.into(),
             None),
        ])
    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        match i {
            0 => {
                pgp.sop()
                    .sign()
                    .key(artifact)
                    .data(crate::tests::MESSAGE)
            },
            1 => {
                pgp.sop()
                    .verify()
                    .cert(data::certificate("bob.pgp"))
                    .signatures(artifact)
                    .data_raw(crate::tests::MESSAGE)
            },
            2 => {
                pgp.sop()
                    .verify()
                    .cert(&self.bob_corrupted)
                    .signatures(artifact)
                    .data_raw(crate::tests::MESSAGE)
            },
            _ => unreachable!(),
        }
    }

    fn check_consumer(&self, i: usize, artifact: &[u8])
                      -> Result<()> {
        match i {
            0 => {
                let p = Packet::from_bytes(artifact)?;
                let s: Signature = p.downcast()
                    .map_err(|p| anyhow::anyhow!("Expected a signature packet, \
                                                  got {:?}", p))?;
                let mut h = s.hash_algo().context()?;
                h.update(crate::tests::MESSAGE);
                s.hash(&mut h);
                let d = h.into_digest()?;
                if s.digest_prefix() == &d[..2] {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Digest prefix mismatch.  \
                                         Got: {:?}, want: {:?}.",
                                        s.digest_prefix(), &d[..2]))
                }
            },
            1 => Ok(()),
            2 => Ok(()),
            _ => unreachable!(),
        }
    }
}
