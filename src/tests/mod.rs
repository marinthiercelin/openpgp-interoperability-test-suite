use crate::{
    Data,
    OpenPGP,
    Result,
    Version,
    templates::Report,
};

mod asymmetric_encryption;
mod symmetric_encryption;
mod detached_signature;
mod hashes;
mod key_generation;

/// Metadata for the tests.
pub trait Test {
    fn title(&self) -> String;
    fn description(&self) -> String;
    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix>;
}

/// Checks that artifacts produced by one implementation can be used
/// by another.
pub trait ProducerConsumerTest : Test {
    fn produce(&self, pgp: &mut OpenPGP) -> Result<Data>;
    fn check_producer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8]) -> Result<Data>;
    fn check_consumer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix>
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
            slug: crate::templates::slug(&self.title()),
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

impl TestMatrix {
    pub fn title(&self) -> String {
        self.title.clone()
    }
}

#[derive(Debug, serde::Serialize)]
struct TestResults {
    artifact: Artifact,
    results: Vec<Artifact>,
}

pub fn schedule(report: &mut Report) -> Result<()> {
    asymmetric_encryption::schedule(report)?;
    symmetric_encryption::schedule(report)?;
    detached_signature::schedule(report)?;
    hashes::schedule(report)?;
    key_generation::schedule(report)?;
    Ok(())
}
