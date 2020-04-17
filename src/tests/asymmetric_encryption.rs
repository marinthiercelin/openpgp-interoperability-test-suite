use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::types::{Features, KeyFlags, Timestamp};
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        Test,
        TestMatrix,
        ProducerConsumerTest,
    },
};

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub struct EncryptDecryptRoundtrip {
    title: String,
    description: String,
    cert: Vec<u8>,
    key: Vec<u8>,
    cipher: Option<openpgp::types::SymmetricAlgorithm>,
    aead: Option<openpgp::types::AEADAlgorithm>,
    message: Data,
}

impl EncryptDecryptRoundtrip {
    pub fn new(title: &str, description: &str, cert: openpgp::Cert,
               message: Data) -> Result<EncryptDecryptRoundtrip> {
        Ok(EncryptDecryptRoundtrip {
            title: title.into(),
            description: description.into(),
            cert: cert.to_vec()?,
            key: cert.as_tsk().to_vec()?,
            cipher: None,
            aead: None,
            message,
        })
    }

    pub fn with_cipher(title: &str, description: &str, cert: openpgp::Cert,
                       message: Data,
                       cipher: openpgp::types::SymmetricAlgorithm,
                       aead: Option<openpgp::types::AEADAlgorithm>)
                       -> Result<EncryptDecryptRoundtrip>
    {
        // Change the cipher preferences of CERT.
        let uid = cert.primary_userid(super::P, None).unwrap();
        let mut builder = openpgp::packet::signature::Builder::from(
            uid.binding_signature().clone())
            .set_signature_creation_time(Timestamp::now())?
            .set_preferred_symmetric_algorithms(vec![cipher])?;
        if let Some(algo) = aead {
            builder = builder.set_preferred_aead_algorithms(vec![algo])?;
            builder = builder.set_features(
                &Features::default().set_mdc(true).set_aead(true))?;
        }
        let mut primary_keypair =
            cert.primary_key()
            .key().clone().parts_into_secret()?.into_keypair()?;
        let new_sig = uid.bind(&mut primary_keypair, &cert, builder)?;
        let cert = cert.merge_packets(vec![new_sig.into()])?;
        let key = cert.as_tsk().to_vec()?;
        let cert = cert.to_vec()?;

        Ok(EncryptDecryptRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            key,
            cipher: Some(cipher),
            aead,
            message,
        })
    }
}

impl Test for EncryptDecryptRoundtrip {
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

impl ProducerConsumerTest for EncryptDecryptRoundtrip {
    fn produce(&self, pgp: &mut OpenPGP)
               -> Result<Data> {
        pgp.encrypt(&self.cert, &self.message)
    }

    fn check_producer(&self, artifact: &[u8]) -> Result<()> {
        if let Some(aead_algo) = self.aead {
            let pp = openpgp::PacketPile::from_bytes(&artifact)
                .context("Produced data is malformed")?;
            match pp.children().last() {
                Some(openpgp::Packet::AED(a)) => {
                    if a.aead() != aead_algo {
                        return Err(anyhow::anyhow!(
                            "Producer did not use {:?}, but {:?}",
                            aead_algo, a.aead()));
                    }

                    if let Some(cipher) = self.cipher {
                        if a.symmetric_algo() != cipher {
                            return Err(anyhow::anyhow!(
                                "Producer did not use {:?} but {:?}",
                                cipher, a.symmetric_algo()));
                        }
                    }
                },
                Some(p) => return
                    Err(anyhow::anyhow!("Producer did not use AEAD, found \
                                              {} packet", p.tag())),
                None => return Err(anyhow::anyhow!("No packet emitted")),
            }
        } else if let Some(cipher) = self.cipher {
            // Check that the producer used CIPHER.
            let cert = openpgp::Cert::from_bytes(&self.key)?;
            let pp = openpgp::PacketPile::from_bytes(&artifact)
                .context("Produced data is malformed")?;
            let mode = KeyFlags::default()
                .set_storage_encryption(true).set_transport_encryption(true);

            let mut ok = false;
            let mut algos = Vec::new();
            'search: for p in pp.children() {
                if let openpgp::Packet::PKESK(p) = p {
                    for ka in cert.keys().with_policy(super::P, None).secret()
                        .key_flags(mode.clone())
                    {
                        let mut keypair = ka.key().clone().into_keypair()?;
                        if let Ok((a, _)) = p.decrypt(&mut keypair, None) {
                            if a == cipher {
                                ok = true;
                                break 'search;
                            }
                            algos.push(a);
                        }
                    }
                }
            }

            if ! ok {
                return Err(anyhow::anyhow!(
                    "Producer did not use {:?}, but {:?}", cipher, algos));
            }
        }

        Ok(())
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(&self.key, &artifact)
    }

    fn check_consumer(&self, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == &self.message[..] {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                     self.message, artifact))
        }
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Asymmetric Encryption");
    report.add(Box::new(
        EncryptDecryptRoundtrip::new(
            "Encrypt-Decrypt roundtrip with key 'Alice'",
            "Encrypt-Decrypt roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::Cert::from_bytes(data::certificate("alice-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())?));
    report.add(Box::new(
        EncryptDecryptRoundtrip::new(
            "Encrypt-Decrypt roundtrip with key 'Bob'",
            "Encrypt-Decrypt roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())?));
    Ok(())
}
