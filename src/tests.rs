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

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub trait ProducerConsumerTest : Test {
    fn produce(&self, pgp: &mut OpenPGP) -> Result<Data>;
    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8]) -> Result<Data>;
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

pub struct EncryptDecryptRoundtrip {
    title: String,
    description: String,
    cert: openpgp::TPK,
    message: Data,
}

impl EncryptDecryptRoundtrip {
    pub fn new(title: &str, description: &str, cert: openpgp::TPK,
               message: Data) -> EncryptDecryptRoundtrip {
        EncryptDecryptRoundtrip {
            title: title.into(),
            description: description.into(),
            cert,
            message,
        }
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

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let plaintext = pgp.decrypt(&self.cert, &artifact)?;
        if &plaintext[..] == &self.message[..] {
            Ok(plaintext)
        } else {
            Err(failure::format_err!("Expected {:?}, got {:?}",
                                     self.message, plaintext))
        }
    }
}

pub fn run_test(implementations: &[Box<dyn OpenPGP>], test: &ProducerConsumerTest)
                -> Result<TestMatrix>
{
    eprint!("  - {}: ", test.title());
    let mut test_results = Vec::new();

    for producer in implementations.iter() {
        let mut p = producer.new_context()?;
        let artifact = match test.produce(p.as_mut()) {
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

        let mut results = Vec::new();
        if artifact.data.len() > 0 {
            for consumer in implementations.iter() {
                let mut c = consumer.new_context()?;
                let plaintext = test.consume(c.as_mut(), &artifact.data);
                eprint!("c");
                results.push(match plaintext {
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
                });
            }
        }

        test_results.push(TestResults { artifact, results} );
    }
    eprintln!(" done.");

    Ok(TestMatrix {
        title: test.title(),
        slug: test.slug(),
        description: test.description(),
        consumers: implementations.iter().map(|i| i.version().unwrap())
            .collect(),
        results: test_results,
    })
}

pub fn all() -> Result<Vec<Box<ProducerConsumerTest>>> {
    use crate::data;
    Ok(vec![
        Box::new(EncryptDecryptRoundtrip::new(
            "Encrypt-Decrypt roundtrip with key 'Alice'",
            "Encrypt-Decrypt roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("alice-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())),
        Box::new(EncryptDecryptRoundtrip::new(
            "Encrypt-Decrypt roundtrip with key 'Bob'",
            "Encrypt-Decrypt roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
            b"Hello, world!".to_vec().into_boxed_slice())),
    ])
}
