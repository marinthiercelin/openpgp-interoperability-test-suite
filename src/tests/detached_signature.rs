use failure::ResultExt;

use sequoia_openpgp as openpgp;
use openpgp::constants::{HashAlgorithm, SignatureType};
use openpgp::parse::Parse;
use openpgp::serialize::{Serialize, SerializeInto};

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
        ProducerConsumerTest,
    },
};

struct DetachedSignatureSubpacket {
    message: Vec<u8>,
}

impl DetachedSignatureSubpacket {
    pub fn new() -> Result<DetachedSignatureSubpacket> {
        Ok(DetachedSignatureSubpacket {
            message: b"huhu".to_vec(),
        })
    }
}

impl Test for DetachedSignatureSubpacket {
    fn title(&self) -> String {
        "Detached signature with Subpackets".into()
    }

    fn description(&self) -> String {
        "Tests how implementations constrain the validity of \
         signatures depending on the given subpackets.".into()
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for DetachedSignatureSubpacket {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        use openpgp::packet::signature::Builder;
        use openpgp::packet::signature::subpacket::{
            Subpacket, SubpacketTag, SubpacketValue, NotationData,
        };

        let cert =
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?;
        let mut primary_keypair =
            cert.primary().clone().mark_parts_secret().into_keypair()?;
        let issuer_fp = primary_keypair.public().fingerprint();
        let issuer = issuer_fp.to_keyid();

        let hash_algo = HashAlgorithm::SHA256;
        let hash_ctx =
            openpgp::crypto::hash_file(std::io::Cursor::new(&self.message),
                                       &[hash_algo])?.pop().unwrap().1;

        let mut make =
            move |test: &str, builder: Builder| -> Result<(String, Data)>
        {
            let mut buf = Vec::new();
            {
                use openpgp::armor;
                let mut w =
                    armor::Writer::new(&mut buf, armor::Kind::Signature, &[])?;
                openpgp::Packet::Signature(builder.sign_hash(
                    &mut primary_keypair, hash_algo,
                    hash_ctx.clone())?).serialize(&mut w)?;
                w.finalize()?;
            }
            Ok((test.into(), buf.into()))
        };

        let now = time::now();

        Ok(vec![
            {
                let test = "Base case";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },

            // Issuer and IssuerFingerprint.
            {
                let test = "No issuer fingerprint";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "No issuer fingerprint, hashed issuer";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "No issuer";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                make(test, builder)?
            },
            {
                let test = "No issuer, unhashed issuer fingerprint";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                make(test, builder)?
            },

            // Creation time.
            {
                let test = "Unhashed creation time";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "No creation time";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "Creation time given twice";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "Future creation time";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now + time::Duration::days(1)), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "Future creation time given twice";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now + time::Duration::days(1)), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now + time::Duration::weeks(1)), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder)?
            },
            {
                let test = "Future creation time, backdated";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now + time::Duration::weeks(1)), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                make(test, builder)?
            },

            // Unknown subpackets.
            {
                let test = "Unknown subpacket";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::with_tag(SubpacketTag::Unknown(127),
                                        SubpacketValue::Unknown(b"value"),
                                        false))?;
                make(test, builder)?
            },
            {
                let test = "Critical unknown subpacket";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::with_tag(SubpacketTag::Unknown(127),
                                        SubpacketValue::Unknown(b"value"),
                                        true))?;
                make(test, builder)?
            },
            {
                let test = "Unknown subpacket, unhashed";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::with_tag(SubpacketTag::Unknown(127),
                                        SubpacketValue::Unknown(b"value"),
                                        false))?;
                make(test, builder)?
            },
            {
                let test = "Critical unknown subpacket, unhashed";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::with_tag(SubpacketTag::Unknown(127),
                                        SubpacketValue::Unknown(b"value"),
                                        true))?;
                make(test, builder)?
            },

            // Unknown notations.
            {
                let test = "Unknown notation";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::NotationData(
                        NotationData::new("unknown@tests.sequoia-pgp.org",
                                          b"value", None)), false)?)?;
                make(test, builder)?
            },
            {
                let test = "Critical unknown notation";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::NotationData(
                        NotationData::new("unknown@tests.sequoia-pgp.org",
                                          b"value", None)), true)?)?;
                make(test, builder)?
            },
            {
                let test = "Unknown notation, unhashed";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::NotationData(
                        NotationData::new("unknown@tests.sequoia-pgp.org",
                                          b"value", None)), false)?)?;
                make(test, builder)?
            },
            {
                let test = "Critical unknown notation, unhashed";
                let mut builder = Builder::new(SignatureType::Binary);
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(now),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::NotationData(
                        NotationData::new("unknown@tests.sequoia-pgp.org",
                                          b"value", None)), true)?)?;
                make(test, builder)?
            },
        ])
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(data::certificate("bob.pgp"), &self.message[..],
                            artifact)
    }
}

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub struct DetachedSignVerifyRoundtrip {
    title: String,
    description: String,
    cert: Vec<u8>,
    key: Vec<u8>,
    hash: Option<HashAlgorithm>,
    message: Data,
}

impl DetachedSignVerifyRoundtrip {
    pub fn new(title: &str, description: &str, cert: openpgp::TPK,
               message: Data) -> Result<DetachedSignVerifyRoundtrip> {
        Ok(DetachedSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            cert: cert.to_vec()?,
            key: cert.as_tsk().to_vec()?,
            hash: None,
            message,
        })
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
        let key = cert.as_tsk().to_vec()?;
        let cert = cert.to_vec()?;

        Ok(DetachedSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            key,
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix> {
        ProducerConsumerTest::run(self, implementations)
    }
}

impl ProducerConsumerTest for DetachedSignVerifyRoundtrip {
    fn produce(&self, pgp: &mut OpenPGP)
               -> Result<Data> {
        pgp.sign_detached(&self.key, &self.message)
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

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Detached Signatures");
    report.add(Box::new(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Alice'",
            "Detached Sign-Verify roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("alice-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())?));
    report.add(Box::new(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Bob'",
            "Detached Sign-Verify roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())?));
    report.add(Box::new(DetachedSignatureSubpacket::new()?));
    Ok(())
}
