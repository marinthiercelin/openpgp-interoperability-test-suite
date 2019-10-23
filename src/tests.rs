use failure::ResultExt;

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    Data,
    OpenPGP,
    Result,
    Version,
};

/// Metadata for the tests.
pub trait Test {
    fn title(&self) -> String;
    fn description(&self) -> String;
    fn slug(&self) -> String {
        let mut slug = String::new();
        for c in self.title().chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => slug.push(c),
                _ => slug.push('_'),
            }
        }
        slug
    }
}

/// Checks that artifacts produced by one implementation can be used
/// by another.
pub trait ProducerConsumerTest : Test {
    fn produce(&self, pgp: &mut OpenPGP) -> Result<Data>;
    fn check_producer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8]) -> Result<Data>;
    fn check_consumer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn run(&self, implementations: &[Box<dyn OpenPGP>]) -> Result<TestMatrix>
    {
        eprint!("  - {}: ", self.title());
        let mut test_results = Vec::new();

        for producer in implementations.iter() {
            let mut p = producer.new_context()?;
            let mut artifact = match self.produce(p.as_mut()) {
                Ok(d) => Artifact {
                    producer: p.version()?,
                    data: d,
                    error: "".into(),
                },
                Err(e) => Artifact {
                    producer: p.version()?,
                    data: Default::default(),
                    error: e.to_string(),
                },
            };
            eprint!("p");
            if artifact.error.len() == 0 {
                if let Err(e) = self.check_producer(&artifact.data) {
                    artifact.error = e.to_string();
                }
            }

            let mut results = Vec::new();
            if artifact.error.len() == 0 {
                for consumer in implementations.iter() {
                    let mut c = consumer.new_context()?;
                    let plaintext = self.consume(c.as_mut(), &artifact.data);
                    eprint!("c");
                    let mut a = match plaintext {
                        Ok(p) =>
                            Artifact {
                                producer: c.version()?,
                                data: p,
                                error: "".into(),
                            },
                        Err(e) =>
                            Artifact {
                                producer: c.version()?,
                                data: Default::default(),
                                error: e.to_string(),
                            },
                    };

                    if a.error.len() == 0 {
                        if let Err(e) = self.check_consumer(&a.data) {
                            a.error = e.to_string();
                        }
                    }

                    results.push(a);
                }
            }

            test_results.push(TestResults { artifact, results} );
        }
        eprintln!(" done.");

        Ok(TestMatrix {
            title: self.title(),
            slug: self.slug(),
            description: self.description(),
            consumers: implementations.iter().map(|i| i.version().unwrap())
                .collect(),
            results: test_results,
        })
    }
}

/// Artifacts produced by producers.
#[derive(Debug, serde::Serialize)]
struct Artifact {
    producer: Version,
    data: Data,
    error: String,
}

#[derive(Debug, serde::Serialize)]
pub struct TestMatrix {
    title: String,
    slug: String,
    description: String,
    consumers: Vec<Version>,
    results: Vec<TestResults>,
}

#[derive(Debug, serde::Serialize)]
struct TestResults {
    artifact: Artifact,
    results: Vec<Artifact>,
}

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub struct EncryptDecryptRoundtrip {
    title: String,
    description: String,
    cert: openpgp::TPK,
    cipher: Option<openpgp::constants::SymmetricAlgorithm>,
    aead: Option<openpgp::constants::AEADAlgorithm>,
    message: Data,
}

impl EncryptDecryptRoundtrip {
    pub fn new(title: &str, description: &str, cert: openpgp::TPK,
               message: Data) -> EncryptDecryptRoundtrip {
        EncryptDecryptRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            cipher: None,
            aead: None,
            message,
        }
    }

    pub fn with_cipher(title: &str, description: &str, cert: openpgp::TPK,
                       message: Data,
                       cipher: openpgp::constants::SymmetricAlgorithm,
                       aead: Option<openpgp::constants::AEADAlgorithm>)
                       -> Result<EncryptDecryptRoundtrip>
    {
        // Change the cipher preferences of CERT.
        let (uidb, sig) = cert.primary_key_signature_full().unwrap();
        let mut builder = openpgp::packet::signature::Builder::from(sig.clone())
            .set_preferred_symmetric_algorithms(vec![cipher])?;
        if let Some(algo) = aead {
            builder = builder.set_preferred_aead_algorithms(vec![algo])?;
        }
        let mut primary_keypair =
            cert.primary().key().clone().mark_parts_secret().into_keypair()?;
        let new_sig = uidb.unwrap().userid().bind(
            &mut primary_keypair,
            &cert, builder, None, None)?;
        let cert = cert.merge_packets(vec![new_sig.into()])?;

        Ok(EncryptDecryptRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
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
                        return Err(failure::format_err!(
                            "Producer did not use {:?}, but {:?}",
                            aead_algo, a.aead()));
                    }

                    if let Some(cipher) = self.cipher {
                        if a.symmetric_algo() != cipher {
                            return Err(failure::format_err!(
                                "Producer did not use {:?} but {:?}",
                                cipher, a.symmetric_algo()));
                        }
                    }
                },
                Some(p) => return
                    Err(failure::format_err!("Producer did not use AEAD, found \
                                              {} packet", p.tag())),
                None => return Err(failure::format_err!("No packet emitted")),
            }
        } else if let Some(cipher) = self.cipher {
            // Check that the producer used CIPHER.
            let pp = openpgp::PacketPile::from_bytes(&artifact)
                .context("Produced data is malformed")?;
            let mode = openpgp::packet::KeyFlags::default()
                .set_encrypt_at_rest(true).set_encrypt_for_transport(true);

            let mut ok = false;
            'search: for p in pp.children() {
                if let openpgp::Packet::PKESK(p) = p {
                    for (_, _, key) in self.cert.keys_all().secret(true)
                        .key_flags(mode.clone())
                    {
                        let mut keypair =
                            key.clone().mark_parts_secret().into_keypair()?;
                        if let Ok((a, _)) = p.decrypt(&mut keypair) {
                            if a == cipher {
                                ok = true;
                                break 'search;
                            }
                        }
                    }
                }
            }

            if ! ok {
                return Err(failure::format_err!("Producer did not use {:?}",
                                                cipher));
            }
        }

        Ok(())
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(&self.cert, &artifact)
    }

    fn check_consumer(&self, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == &self.message[..] {
            Ok(())
        } else {
            Err(failure::format_err!("Expected {:?}, got {:?}",
                                     self.message, artifact))
        }
    }
}

pub fn all() -> Result<Vec<Box<ProducerConsumerTest>>> {
    use crate::data;
    let mut tests: Vec<Box<ProducerConsumerTest>> = Vec::new();
    tests.push(
        Box::new(EncryptDecryptRoundtrip::new(
            "Encrypt-Decrypt roundtrip with key 'Alice'",
            "Encrypt-Decrypt roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("alice-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())));
    tests.push(
        Box::new(EncryptDecryptRoundtrip::new(
            "Encrypt-Decrypt roundtrip with key 'Bob'",
            "Encrypt-Decrypt roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())));

    use openpgp::constants::SymmetricAlgorithm::*;
    for &cipher in &[IDEA, TripleDES, CAST5, Blowfish, AES128, AES192, AES256,
                     Twofish, Camellia128, Camellia192, Camellia256] {
        tests.push(
            Box::new(EncryptDecryptRoundtrip::with_cipher(
                &format!("Encrypt-Decrypt roundtrip with key 'Bob', {:?}",
                         cipher),
                &format!("Encrypt-Decrypt roundtrip using the 'Bob' key from \
                          draft-bre-openpgp-samples-00, modified with the \
                          symmetric algorithm preference [{:?}].", cipher),
                openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), cipher, None)?));
    }
    use openpgp::constants::AEADAlgorithm::*;
    for &aead_algo in &[EAX, OCB] {
        tests.push(
            Box::new(EncryptDecryptRoundtrip::with_cipher(
                &format!("Encrypt-Decrypt roundtrip with key 'Bob', {:?}",
                         aead_algo),
                &format!("Encrypt-Decrypt roundtrip using the 'Bob' key from \
                          draft-bre-openpgp-samples-00, modified with the \
                          symmetric algorithm preference [AES256], \
                          AEAD algorithm preference [{:?}].", aead_algo),
                openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), AES256,
                Some(aead_algo))?));
    }

    Ok(tests)
}
