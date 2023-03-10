use std::convert::TryInto;
use std::io::Write;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::types::{HashAlgorithm, SignatureType, Timestamp};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::Parse;
use openpgp::serialize::{Serialize, SerializeInto, stream::*};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::TestPlan,
    tests::{
        Expectation,
        TestMatrix,
        ConsumerTest,
        ProducerConsumerTest,
    },
};

mod unknown_packets;
mod short_rsa_sigs;
mod digest_prefix;

struct DetachedSignatureSubpacket {
    message: Vec<u8>,
}

impl DetachedSignatureSubpacket {
    pub fn new() -> Result<DetachedSignatureSubpacket> {
        Ok(DetachedSignatureSubpacket {
            message: crate::tests::MESSAGE.to_vec(),
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for DetachedSignatureSubpacket {
    fn title(&self) -> String {
        "Detached signature with Subpackets".into()
    }

    fn description(&self) -> String {
        format!(
            "Tests how implementations constrain the validity of \
             signatures depending on the given subpackets.  \
             The test signs the message {:?}.",
            String::from_utf8_lossy(&self.message))
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }

    fn tags(&self) -> std::collections::BTreeSet<&'static str> {
        ["verify-only"].iter().cloned().collect()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for DetachedSignatureSubpacket {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::packet::Signature;
        use openpgp::packet::signature::subpacket::{
            Subpacket,
            SubpacketTag,
            SubpacketValue, NotationData,
        };

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let issuer_fp = cert.fingerprint();
        let issuer: openpgp::KeyID = issuer_fp.clone().into();

        let hash_algo = HashAlgorithm::SHA256;
        let mut hash_ctx = hash_algo.context()?;
        hash_ctx.update(&self.message);

        let make_sig = move |builder: SignatureBuilder| -> Result<Signature>
        {
            let mut primary_keypair =
                cert.primary_key()
                .key().clone().parts_into_secret()?.into_keypair()?;
            builder.sign_hash(&mut primary_keypair, hash_ctx.clone())
        };

        let make_armor = |sig: Signature| -> Result<Data> {
            let mut buf = Vec::new();
            {
                let mut w =
                    armor::Writer::new(&mut buf, armor::Kind::Signature)?;
                openpgp::Packet::Signature(sig).serialize(&mut w)?;
                w.finalize()?;
            }
            Ok(buf.into())
        };

        let make =
            |test: &str, builder: SignatureBuilder, e: Option<Expectation>|
            -> Result<(String, Data, Option<Expectation>)>
        {
            Ok((test.into(), make_armor(make_sig(builder)?)?, e))
        };

        let now = std::time::SystemTime::now();
        let one_day = std::time::Duration::new(1 * 24 * 60 * 60, 0);
        let one_week = 7 * one_day;

        Ok(vec![
            {
                let test = "Base case";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Base case, unhashed issuer fingerprint";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Base case, hashed issuer";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },

            // Issuer and IssuerFingerprint.
            {
                let test = "No issuer fingerprint";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "No issuer fingerprint, hashed issuer";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "No issuer";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                make(test, builder,
                     Some(Ok("Issuer fingerprint ought to be enough.".into())))?
            },
            {
                let test = "No issuer, unhashed issuer fingerprint";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                make(test, builder,
                     Some(Ok("Issuer fingerprint ought to be enough.".into())))?
            },
            {
                let test = "No issuer, no issuer fingerprint";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                // We need to add issuer information and remove it
                // after signing.
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(
                        issuer.clone()), false)?)?;

                let mut sig = make_sig(builder)?;
                sig.unhashed_area_mut().clear();
                assert_eq!(sig.issuers().count(), 0);
                assert_eq!(sig.issuer_fingerprints().count(), 0);
                (test.into(), make_armor(sig)?, None)
            },

            // Multiple issuer informations.
            {
                let test = "Issuer, fake issuer";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(
                        "AAAA BBBB CCCC DDDD".parse()?),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Fake issuer, issuer";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(
                        "AAAA BBBB CCCC DDDD".parse()?),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Issuer, fake issuer, V6 issuer FP";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(
                        "AAAA BBBB CCCC DDDD".parse()?),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::IssuerFingerprint,
                        body: vec![
                            6, // Fictitious version 6 fingerprint
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, // 34 bytes of fictitious fingerprint
                        ],
                    }, false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Fake issuer, issuer, V6 issuer FP";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(
                        "AAAA BBBB CCCC DDDD".parse()?),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::IssuerFingerprint,
                        body: vec![
                            6, // Fictitious version 6 fingerprint
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                            0xAA, 0xAA, // 34 bytes of fictitious fingerprint
                        ],
                    }, false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },

            // Creation time.
            {
                let test = "Unhashed creation time";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder = builder.suppress_signature_creation_time()?;
                builder.hashed_area_mut().clear();
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Err("Creation time must be hashed.".into())))?
            },
            {
                let test = "No creation time";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder = builder.suppress_signature_creation_time()?;
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                let sig = make_sig(builder)?;
                assert!(sig.signature_creation_time().is_none());
                (test.into(), make_armor(sig)?,
                 Some(Err("Creation time must exist.".into())))
            },
            {
                let test = "Creation time given twice";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder = builder.suppress_signature_creation_time()?;
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Ok("Uniqueness of subpackets is not required."
                             .into())))?
            },
            {
                let test = "Future creation time";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder = builder.suppress_signature_creation_time()?;
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        (now + one_day).try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Err("Creation time is in the future.".into())))?
            },
            {
                let test = "Future creation time given twice";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder = builder.suppress_signature_creation_time()?;
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        (now + one_day).try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        (now + one_week).try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                make(test, builder,
                     Some(Err("Creation time is in the future.".into())))?
            },
            {
                let test = "Future creation time, backdated";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder = builder.suppress_signature_creation_time()?;
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        (now + one_week).try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                make(test, builder,
                     Some(Err("Creation time is in the future.".into())))?
            },

            // Unknown subpackets.
            {
                let test = "Unknown subpacket";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::Unknown(127),
                        body: b"value".to_vec(),
                    }, false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Critical unknown subpacket";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::Unknown(127),
                        body: b"value".to_vec(),
                    }, true)?)?;
                make(test, builder,
                     Some(Err("Critical unknown subpacket invalidates signature."
                              .into())))?
            },
            {
                let test = "Unknown subpacket, unhashed";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::Unknown(127),
                        body: b"value".to_vec(),
                    }, false)?)?;
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Critical unknown subpacket, unhashed";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                                   false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::Unknown(127),
                        body: b"value".to_vec(),
                    }, true)?)?;
                make(test, builder, None)?
            },

            // Unknown notations.
            {
                let test = "Unknown notation";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
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
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Critical unknown notation";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
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
                make(test, builder,
                     Some(Err("Critical unknown notation invalidates signature."
                              .into())))?
            },
            {
                let test = "Unknown notation, unhashed";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
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
                make(test, builder,
                     Some(Ok("Interoperability concern.".into())))?
            },
            {
                let test = "Critical unknown notation, unhashed";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignatureCreationTime(
                        now.try_into()?), false)?)?;
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
                make(test, builder, None)?
            },

            // Signer's User-ID
            {
                let test = "Signer's User-ID without a match";
                let mut builder = SignatureBuilder::new(SignatureType::Binary);
                let unmatched_user_id = "Uli Unmatched <uli@openpgp.example>";

                builder.hashed_area_mut().clear();
                builder.hashed_area_mut().add(
                Subpacket::new(SubpacketValue::SignatureCreationTime(
                    now.try_into()?), false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::IssuerFingerprint(
                        issuer_fp.clone()), false)?)?;
                builder.unhashed_area_mut().add(
                    Subpacket::new(SubpacketValue::Issuer(issuer.clone()),
                        false)?)?;
                builder.hashed_area_mut().add(
                    Subpacket::new(SubpacketValue::SignersUserID(
                        unmatched_user_id.as_bytes().to_vec()),
                            false)?)?;
                make(test, builder, None)?
            },
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
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
    expectation: Option<Expectation>,
}

impl DetachedSignVerifyRoundtrip {
    pub fn new(title: &str, description: &str, key: &[u8], cert: &[u8],
               message: Data,
               expectation: Option<Expectation>)
               -> Result<DetachedSignVerifyRoundtrip>
    {
        Ok(DetachedSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            cert: cert.into(),
            key: key.into(),
            hash: None,
            message,
            expectation,
        })
    }

    pub fn with_hash(title: &str, description: &str, cert: openpgp::Cert,
                     message: Data,
                     hash: HashAlgorithm)
                     -> Result<DetachedSignVerifyRoundtrip>
    {
        // Change the hash algorithm preferences of CERT.
        let uid = cert.with_policy(super::P, None).unwrap()
            .primary_userid().unwrap();
        let builder = SignatureBuilder::from(uid.binding_signature().clone())
            .set_signature_creation_time(Timestamp::now())?
            .set_preferred_hash_algorithms(vec![hash])?;
        let mut primary_keypair =
            cert.primary_key()
            .key().clone().parts_into_secret()?.into_keypair()?;
        let new_sig = uid.bind(
            &mut primary_keypair, &cert, builder)?;
        let cert = cert.insert_packets(Some(new_sig))?;
        let key = cert.as_tsk().armored().to_vec()?;
        let cert = cert.armored().to_vec()?;

        Ok(DetachedSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            key,
            hash: Some(hash),
            message,
            expectation: Some(Ok("Interoperability concern.".into())),
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for DetachedSignVerifyRoundtrip {
    fn title(&self) -> String {
        self.title.clone()
    }

    fn description(&self) -> String {
        self.description.clone()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), self.cert.clone().into())]
    }

    fn run(&self, implementations: &[crate::Sop]) -> Result<TestMatrix> {
        ProducerConsumerTest::run(self, implementations)
    }
}

impl ProducerConsumerTest for DetachedSignVerifyRoundtrip {
    fn produce(&self, pgp: &dyn OpenPGP)
               -> Result<Data> {
        pgp.sign_detached(&self.key, &self.message)
    }

    fn check_producer(&self, artifact: Data) -> Result<Data> {
        let pp = openpgp::PacketPile::from_bytes(&artifact)
            .context("Produced data is malformed")?;
        if pp.children().count() != 1 {
            return Err(anyhow::anyhow!(
                "Producer produced more than one packet: {:?}",
                pp.children().collect::<Vec<_>>()));
        }

        match pp.children().next().unwrap() {
            openpgp::Packet::Signature(p) =>
                if let Some(hash) = self.hash {
                    if p.hash_algo() != hash {
                        return Err(anyhow::anyhow!(
                            "Producer did not use {:?}, but {:?}",
                            hash, p.hash_algo()));
                    }
                },

            p => return
                Err(anyhow::anyhow!(
                    "Producer did produce an Signature packet, found \
                     {:?} packet", p)),
        }

        Ok(artifact)
    }

    fn consume(&self,
               _producer: &dyn OpenPGP,
               consumer: &dyn OpenPGP,
               artifact: &[u8])
               -> Result<Data> {
        consumer.verify_detached(&self.cert, &self.message, &artifact)
    }

    fn expectation(&self) -> Option<Expectation> {
        if let Some(hash) = self.hash {
            use HashAlgorithm::*;
            match hash {
                MD5 | SHA1 | RipeMD =>
                    Some(Err("Hash should not be used anymore.".into())),
                SHA256 =>
                    Some(Ok("MUST be implemented according to RFC4880bis8."
                            .into())),
                SHA384 | SHA512 =>
                    Some(Ok("Should be supported.".into())),
                _ =>
                    Some(Ok("Interoperability concern.".into())),
            }
        } else {
            self.expectation.clone()
        }
    }
}

struct LineBreakNormalizationTest {
}

impl LineBreakNormalizationTest {
    pub fn new() -> Result<LineBreakNormalizationTest> {
        Ok(LineBreakNormalizationTest {
        })
    }

    const N_VECTORS: usize = 21;
    const N_PLAUSIBLE_VECTORS: usize = 12;
    fn test_vector(i: usize)
                   -> (SignatureType, &'static [u8], Option<Expectation>)
    {
        let binary = (i & 1) == 0;
        let idx = i >> 1;
        let data = match idx {
            0 => &b"one\r\ntwo\r\nthree"[..], // dos
            1 => b"one\ntwo\nthree",          // unix
            2 => b"one\ntwo\r\nthree",        // mixed
            3 => b"one\r\ntwo\nthree",
            // Obscure endings below.
            4 => b"one\rtwo\rthree",          // classic mac
            5 => b"one\n\rtwo\n\rthree",      // risc os
            6 => b"one\x1etwo\x1ethree",      // classic qnx
            7 => b"one\x0btwo\x0bthree",      // line feed
            8 => b"one\x0ctwo\x0cthree",      // form feed
            // Unicode endings below.
            9 => "one\u{85}two\u{85}three".as_bytes(), // Next Line
            10 => "one\u{2028}two\u{2028}three".as_bytes(), // Line Separator
            11 => "one\u{2029}two\u{2029}three".as_bytes(), // Paragraph Separator
            // Trailing whitespace below.
            12 => b"one \ntwo\nthree",
            13 => b"one\ntwo \nthree",
            14 => b"one\ntwo\nthree ",
            15 => b"one\ntwo\nthree\n",
            16 => b"\none\ntwo\nthree",
            17 => b"one\t\ntwo\nthree",
            18 => "one\u{a0}\ntwo\nthree".as_bytes(),
            19 => "one\u{1680}\ntwo\nthree".as_bytes(),
            20 => "one\u{2000}\ntwo\nthree".as_bytes(),
            // XXX: This is getting repetitive... Clamping N_VECTORS
            // to 21...
            21 => "one\u{2001}\ntwo\nthree".as_bytes(),
            22 => "one\u{2002}\ntwo\nthree".as_bytes(),
            23 => "one\u{2003}\ntwo\nthree".as_bytes(),
            24 => "one\u{2004}\ntwo\nthree".as_bytes(),
            25 => "one\u{2005}\ntwo\nthree".as_bytes(),
            26 => "one\u{2006}\ntwo\nthree".as_bytes(),
            27 => "one\u{2007}\ntwo\nthree".as_bytes(),
            28 => "one\u{2008}\ntwo\nthree".as_bytes(),
            29 => "one\u{2009}\ntwo\nthree".as_bytes(),
            30 => "one\u{200a}\ntwo\nthree".as_bytes(),
            31 => "one\u{202f}\ntwo\nthree".as_bytes(),
            32 => "one\u{205f}\ntwo\nthree".as_bytes(),
            33 => "one\u{3000}\ntwo\nthree".as_bytes(),
            Self::N_VECTORS..=std::usize::MAX =>
                panic!("Invalid test vector {}", i),
            _ => unreachable!(),
        };
        let expectation = match (binary, idx) {
            (true, 0) => Some(Ok("Base case (b)".into())),
            (false, 0) => Some(Ok("Base case (t)".into())),
            (true, _) =>
                Some(Err("Binary signature must not be valid (b)".into())),
            (false, n) if n < 4 =>
                Some(Ok("Line endings must be normalized (t)".into())),
            (false, n) if n >= Self::N_PLAUSIBLE_VECTORS =>
                Some(Err("Erroneous normalization \
                          (e.g. trailing whitespace) (t)".into())),
            (false, _) => None,
        };

        (if binary { SignatureType::Binary } else { SignatureType::Text },
         data,
         expectation)
    }
}

impl crate::plan::Runnable<TestMatrix> for LineBreakNormalizationTest {
    fn title(&self) -> String {
        "Detached signatures: Linebreak normalization".into()
    }

    fn description(&self) -> String {
        "<p>Tests how implementations normalize line breaks when \
         verifying text signatures.  Section 5.2.1 of RFC4880 says: \
         <q>The signature is calculated over the text data with its \
         line endings converted to &lt;CR&gt;&lt;LF&gt;.</q></p>\
         \
         <p>This test creates two signatures, a binary and a text \
         signature, over the message <q>one\\r\\ntwo\\r\\nthree</q>, \
         and checks whether variants of the message with different \
         line endings can be verified using these signatures.</p>"
            .into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }

    fn tags(&self) -> std::collections::BTreeSet<&'static str> {
        ["verify-only"].iter().cloned().collect()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for LineBreakNormalizationTest {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;

        let mut binary = vec![];
        {
            let signing_keypair =
                cert.primary_key()
                .key().clone().parts_into_secret()?.into_keypair()?;

            let message = Message::new(&mut binary);
            let message = Armorer::new(message)
                .kind(armor::Kind::Signature)
                .build()?;
            let b = SignatureBuilder::new(SignatureType::Binary);
            let mut signer = Signer::with_template(message, signing_keypair, b)
                .detached()
                .build()?;
            signer.write_all(Self::test_vector(0).1)?;
            signer.finalize()?;
        }
        let binary: Data = binary.into();

        let mut text = vec![];
        {
            let signing_keypair =
                cert.primary_key()
                .key().clone().parts_into_secret()?.into_keypair()?;

            let message = Message::new(&mut text);
            let message = Armorer::new(message)
                .kind(armor::Kind::Signature)
                .build()?;
            let b = SignatureBuilder::new(SignatureType::Text);
            let mut signer = Signer::with_template(message, signing_keypair, b)
                .detached()
                .build()?;
            signer.write_all(Self::test_vector(0).1)?;
            signer.finalize()?;
        }
        let text: Data = text.into();

        Ok((0..Self::N_VECTORS * 2).into_iter().map(|i| {
            let (typ, data, expectation) = Self::test_vector(i);
            (format!("{:?}", String::from_utf8(data.to_vec()).unwrap()),
             match typ {
                 SignatureType::Binary => binary.clone(),
                 SignatureType::Text => text.clone(),
                 _ => panic!("unexpected signature type: {:?}", typ),
             },
             expectation)
        }).collect())
    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let (_, message, _) = Self::test_vector(i);
        pgp.verify_detached(data::certificate("bob.pgp"), message, artifact)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Detached Signatures");
    plan.add(Box::new(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Alice'",
            "Detached Sign-Verify roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            data::certificate("alice-secret.pgp"),
            data::certificate("alice.pgp"),
            crate::tests::MESSAGE.to_vec().into(),
            Some(Ok("Interoperability concern.".into())))?));
    plan.add(Box::new(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Bob'",
            "Detached Sign-Verify roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            crate::tests::MESSAGE.to_vec().into(),
            Some(Ok("Interoperability concern.".into())))?));
    plan.add(Box::new(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'Carol'",
            "Detached Sign-Verify roundtrip using the 'Carol' key from \
             draft-bre-openpgp-samples-00.",
            data::certificate("carol-secret.pgp"),
            data::certificate("carol.pgp"),
            crate::tests::MESSAGE.to_vec().into(),
            Some(Ok("Interoperability concern.".into())))?));
    plan.add(Box::new(
        DetachedSignVerifyRoundtrip::new(
            "Detached Sign-Verify roundtrip with key 'John'",
            "This is an OpenPGP v3 key.",
            data::certificate("john-secret.pgp"),
            data::certificate("john.pgp"),
            crate::tests::MESSAGE.to_vec().into(),
            None)?));
    plan.add(Box::new(DetachedSignatureSubpacket::new()?));
    plan.add(Box::new(LineBreakNormalizationTest::new()?));
    plan.add(Box::new(unknown_packets::UnknownPackets::new()?));
    plan.add(Box::new(short_rsa_sigs::ShortRSASigs::new()?));
    plan.add(Box::new(digest_prefix::DigestPrefix::new()?));
    Ok(())
}
