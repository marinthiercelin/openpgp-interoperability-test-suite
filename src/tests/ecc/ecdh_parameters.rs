use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::*,
    packet::prelude::*,
    parse::Parse,
    serialize::MarshalInto,
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

/// Tests whether implementations can use Cv25519 keys that use
/// unusual ECDH parameters.
pub struct ECDHParameters {
    key: openpgp::Cert,
}

impl ECDHParameters {
    pub fn new() -> Result<ECDHParameters> {
        let key =
            openpgp::Cert::from_bytes(data::certificate("alice-secret.pgp"))?;
        Ok(ECDHParameters {
            key,
        })
    }
}

impl Test for ECDHParameters {
    fn title(&self) -> String {
        "ECDH Parameters".into()
    }

    fn description(&self) -> String {
        "Tests whether implementations can use Cv25519 keys that use \
         unusual ECDH parameters.".into()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for ECDHParameters {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use mpi::PublicKey;
        let key_wo_subkey = self.key.clone().retain_subkeys(|_| false);
        let mut primary_signer =
            key_wo_subkey.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let subkey =
            self.key.keys().subkeys().next().unwrap().key();
        let subkey_binding =
            self.key.keys().subkeys().next().unwrap()
            .self_signatures().next().unwrap();

        // Returns the cert with the given ECDH parameters.
        let mut modify_key =
            |func: &dyn Fn(&PublicKey) -> PublicKey| -> Result<openpgp::Cert> {
                let cert = key_wo_subkey.clone();
                let mut s = subkey.clone();
                s.set_mpis(func(subkey.mpis()));

                let template = SignatureBuilder::from(subkey_binding.clone())
                    .set_signature_creation_time(
                        subkey_binding.signature_creation_time().unwrap())?;
                let b = s.bind(&mut primary_signer, &cert, template)?;

                cert.insert_packets(vec![Packet::from(s), b.into()])
            };

        use crate::tests::certificates::make_test as make;
        let mut tests = vec![
            make("Base case", modify_key(&|pk: &PublicKey| pk.clone())?,
                 Some(Ok("Interoperability concern".into())))?,
            make("Fictitious v0", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 3] = 0;
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("Fictitious v2", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 3] = 2;
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("No KDF parameters", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest.truncate(l - 4);
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("KDF size octet = 0", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 4] = 0;
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("KDF size octet = 2", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 4] = 2;
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("KDF size octet = 4", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 4] = 4;
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("KDF size octet = 0xff", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 4] = 0xff;
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

            make("KDF size octet = 4 + extra zero", modify_key(&|pk: &PublicKey| {
                let mut rest = pk.to_vec().unwrap();
                let l = rest.len();
                rest[l - 4] = 4;
                rest.push(0);
                PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: rest.into(),
                }
            })?, None)?,

        ];

        use openpgp::types::{HashAlgorithm::*, SymmetricAlgorithm::*};
        for &sym in crate::tests::symmetric_encryption::CIPHERS {
            for &hash in crate::tests::hashes::HASHES {
                tests.push(
                    make(&format!("{:?}, {:?}", sym, hash),
                         modify_key(&|pk: &PublicKey| {
                             if let PublicKey::ECDH { curve, q, .. } =
                                 pk.clone()
                             {
                                 PublicKey::ECDH {
                                     curve,
                                     q,
                                     hash,
                                     sym,
                                 }
                             } else {
                                 panic!("Expected an ECDH key: {:?}", pk);
                             }
                         })?,
                         match (hash, sym) {
                             (SHA256, AES128) => Some(Ok("RFC6637 MUST".into())),
                             | (SHA256, AES256)
                             | (SHA384, AES128)
                             | (SHA384, AES256)
                             | (SHA512, AES128)
                             | (SHA512, AES256)
                                 => Some(Ok("RFC6637 SHOULD".into())),
                             | (MD5, _)
                             | (SHA1, _)
                             | (RipeMD, _)
                             | (_, IDEA)
                             | (_, TripleDES)
                             | (_, CAST5)
                             | (_, Blowfish)
                                 => Some(Err("Dubious algorithm".into())),
                             _ => None,
                         })?
                );
            }
        }

        Ok(tests)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.sop().encrypt()
           .cert(&crate::tests::extract_cert(artifact)?)
           .plaintext(crate::tests::MESSAGE)?;
        Ok(pgp.sop().decrypt()
           .key(artifact)
           .ciphertext(&ciphertext)?.1)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == crate::tests::MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!("Expected {:?}, got {:?}",
                                        crate::tests::MESSAGE,
                                        artifact)))
        }
    }
}
