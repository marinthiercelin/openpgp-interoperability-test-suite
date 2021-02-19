use std::{
    collections::HashMap,
};

use sequoia_openpgp as openpgp;
use openpgp::policy::StandardPolicy;

use crate::{
    Data,
    OpenPGP,
    Result,
    Version,
    templates::Report,
};

mod asymmetric_encryption;
mod symmetric_encryption;
mod detached_signatures;
mod hashes;
mod compression;
mod key_generation;
mod certificates;
mod messages;
mod ecc;
mod packet_parser;
mod armor;

/// A StandardPolicy for the tests to use.
const P: &StandardPolicy = &StandardPolicy::new();

/// Metadata for the tests.
pub trait Test {
    fn title(&self) -> String;
    fn description(&self) -> String;
    fn artifacts(&self) -> Vec<(String, Data)> {
        Vec::with_capacity(0)
    }
    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix>;
}

/// States the expected result of a test.
type Expectation = std::result::Result<String, String>;

/// Checks that artifacts can be used by all implementations.
pub trait ConsumerTest : Test {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>>;
    fn consume(&self, i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data>;
    fn check_consumer(&self, _i: usize, _artifact: &[u8])
                      -> Result<()> {
        Ok(())
    }
    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix>
    {
        let mut test_results = Vec::new();

        for (i, (description, data, expectation))
            in self.produce()?.into_iter().enumerate()
        {
            let artifact = Artifact::ok(description, data);

            let mut results = Vec::new();
            for consumer in implementations.iter() {
                let mut c = consumer.new_context()?;
                let plaintext = self.consume(i, c.as_mut(), &artifact.data);
                let mut a = match plaintext {
                    Ok(p) =>
                        Artifact::ok(c.version()?.to_string(), p),
                    Err(e) =>
                        Artifact::err(c.version()?.to_string(),
                                      Default::default(), e),
                };

                if a.error.len() == 0 {
                    if let Err(e) = self.check_consumer(i, &a.data) {
                        a.error = e.to_string();
                    }
                }

                a.set_score(&expectation);
                results.push(a);
            }

            test_results.push(TestResults {
                artifact: artifact.limit_data_size(),
                results,
                expectation,
            });
        }

        Ok(TestMatrix {
            title: self.title(),
            slug: crate::templates::slug(&self.title()),
            description: self.description(),
            artifacts: self.artifacts(),
            consumers: implementations.iter().map(|i| i.version().unwrap())
                .collect(),
            results: test_results,
        })
    }
}

/// Checks that artifacts produced by one implementation can be used
/// by another.
pub trait ProducerConsumerTest : Test {
    fn produce(&self, pgp: &mut dyn OpenPGP) -> Result<Data>;
    fn check_producer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn consume(&self,
               producer: &mut dyn OpenPGP,
               consumer: &mut dyn OpenPGP,
               artifact: &[u8]) -> Result<Data>;
    fn check_consumer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn expectation(&self) -> Option<Expectation> {
        Some(Ok("Interoperability concern.".into()))
    }
    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix>
    {
        let mut test_results = Vec::new();

        for producer in implementations.iter() {
            let expectation = self.expectation();
            let mut p = producer.new_context()?;
            let mut artifact = match self.produce(p.as_mut()) {
                Ok(d) => Artifact::ok(p.version()?.to_string(), d),
                Err(e) => Artifact::err(p.version()?.to_string(),
                                        Default::default(), e),
            };
            if artifact.error.len() == 0 {
                if let Err(e) = self.check_producer(&artifact.data) {
                    artifact.error = e.to_string();
                }
            }

            let mut results = Vec::new();
            if artifact.error.len() == 0 {
                for consumer in implementations.iter() {
                    let mut p = producer.new_context()?;
                    let mut c = consumer.new_context()?;
                    let plaintext =
                        self.consume(p.as_mut(), c.as_mut(),
                                     &artifact.data);
                    let mut a = match plaintext {
                        Ok(p) =>
                            Artifact::ok(c.version()?.to_string(), p),
                        Err(e) =>
                            Artifact::err(c.version()?.to_string(),
                                          Default::default(), e),
                    };

                    if a.error.len() == 0 {
                        if let Err(e) = self.check_consumer(&a.data) {
                            a.error = e.to_string();
                        }
                    }

                    a.set_score(&expectation);
                    results.push(a);
                }
            }

            test_results.push(TestResults {
                artifact: artifact.limit_data_size(),
                results,
                expectation,
            });
        }

        Ok(TestMatrix {
            title: self.title(),
            slug: crate::templates::slug(&self.title()),
            description: self.description(),
            artifacts: self.artifacts(),
            consumers: implementations.iter().map(|i| i.version().unwrap())
                .collect(),
            results: test_results,
        })
    }
}

/// Artifacts produced by producers.
#[derive(Debug, serde::Serialize)]
struct Artifact {
    producer: String,
    data: Data,
    error: String,
    score: Option<bool>,
    score_class: &'static str,
}

impl Artifact {
    fn ok(producer: String, data: Data) -> Self {
        Self {
            producer,
            data,
            error: Default::default(),
            score: None,
            score_class: "score",
        }
    }

    fn err(producer: String, data: Data, err: anyhow::Error) -> Self {
        use std::fmt::Write;
        let mut error = String::new();
        writeln!(error, "{}", err).unwrap();
        err.chain().skip(1)
            .for_each(|cause| writeln!(error, "  because: {}", cause).unwrap());

        Self {
            producer,
            data,
            error,
            score: None,
            score_class: "score",
        }
    }

    fn set_score(&mut self, expectation: &Option<Expectation>) {
        self.score =
            expectation.as_ref().map(|e| e.is_err() == (self.error.len() > 0));
        match self.score {
            None => (),
            Some(true) => self.score_class = "score-good",
            Some(false) => self.score_class = "score-bad",
        }
    }

    /// Limits the artifact size.
    ///
    /// In order not to bloat the report too much, we limit the size
    /// of artifacts included in the report.  If the data exceeds the
    /// configured size, it is dropped.
    fn limit_data_size(mut self) -> Self {
        if self.data.len() > crate::MAXIMUM_ARTIFACT_SIZE {
            self.data = Default::default();
        }
        self
    }
}

#[derive(Debug, serde::Serialize)]
pub struct TestMatrix {
    title: String,
    slug: String,
    description: String,
    artifacts: Vec<(String, Data)>,
    consumers: Vec<Version>,
    results: Vec<TestResults>,
}

impl TestMatrix {
    pub fn title(&self) -> String {
        self.title.clone()
    }

    pub fn summarize(&self, summary: &mut Summary) {
        for (i, imp) in self.consumers.iter().enumerate() {
            let mut good = 0;
            let mut bad = 0;

            for row in &self.results {
                // Get the result corresponding to implementation
                // 'imp'.
                if let Some(r) = row.results.get(i) {
                    match r.score {
                        None => (),
                        Some(true) => good += 1,
                        Some(false) => bad += 1,
                    }
                }
            }

            // Count all rows where we have an expectation, and the
            // producer produced an artifact.
            let have_expectations = self.results.iter().filter(|row| {
                row.expectation.is_some() && ! row.results.is_empty()
            }).count();

            // Did it pass on all test vectors?
            let all_good = good == have_expectations;

            summary.add(imp.clone(), good, bad, all_good);
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct TestResults {
    artifact: Artifact,
    results: Vec<Artifact>,
    expectation: Option<Expectation>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct Summary {
    score: HashMap<Version, Scores>,
}

impl Summary {
    fn add(&mut self, imp: Version, good: usize, bad: usize, all_good: bool) {
        let e = self.score.entry(imp).or_default();
        e.good += good;
        e.bad += bad;
        if all_good {
            e.all_good += 1;
        }
    }

    /// Transforms the summary into a map suitable for rendering.
    pub fn for_rendering(self) -> Vec<(String, Scores)> {
        let mut r: Vec<(String, Scores)> =
            self.score.into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        r.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse());
        r
    }
}

#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Scores {
    good: usize,
    bad: usize,
    all_good: usize,
}

impl Ord for Scores {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.all_good.cmp(&other.all_good)
            .then(self.good.cmp(&other.good))
            .then(self.bad.cmp(&other.bad).reverse())
    }
}

impl PartialOrd for Scores {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Extracts the public certificate from the given key.
pub fn extract_cert(key: &[u8]) -> Result<Data> {
    use openpgp::Packet;
    use openpgp::parse::{Parse, PacketParser, PacketParserResult};
    use openpgp::serialize::Serialize;
    let mut cert = Vec::new();

    let mut ppr = PacketParser::from_bytes(key)?;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, ppr_) = pp.next()?;
        ppr = ppr_;
        match packet {
            Packet::SecretKey(k) =>
                Packet::PublicKey(k.parts_into_public())
                    .serialize(&mut cert)?,
            Packet::SecretSubkey(k) =>
                Packet::PublicSubkey(k.parts_into_public())
                    .serialize(&mut cert)?,
            p => p.serialize(&mut cert)?,
        }
    }

    Ok(cert.into_boxed_slice())
}

pub fn schedule(report: &mut Report) -> Result<()> {
    asymmetric_encryption::schedule(report)?;
    symmetric_encryption::schedule(report)?;
    detached_signatures::schedule(report)?;
    hashes::schedule(report)?;
    compression::schedule(report)?;
    key_generation::schedule(report)?;
    certificates::schedule(report)?;
    messages::schedule(report)?;
    armor::schedule(report)?;
    ecc::schedule(report)?;
    packet_parser::schedule(report)?;
    Ok(())
}
