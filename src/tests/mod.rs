use std::{
    collections::{BTreeSet, HashMap},
};

use sequoia_openpgp as openpgp;
use openpgp::policy::StandardPolicy;

use crate::{
    Data,
    OpenPGP,
    Result,
    sop::Version,
    plan::{
        Plan,
        Runnable,
    },
};

pub mod templates;

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

/// Message used in tests.
///
/// For consistency, all tests that sign/encrypt a message should use
/// this statement.
pub const MESSAGE: &[u8] = b"Hello World :)";

/// Password used in tests.
///
/// For consistency, all tests that encrypt a message should use this
/// password.
pub const PASSWORD: &str = "password";

/// A StandardPolicy for the tests to use.
const P: &StandardPolicy = &StandardPolicy::new();

/// Metadata for the tests.
pub trait Test: Runnable<TestMatrix> {
}

/// States the expected result of a test.
type Expectation = std::result::Result<String, String>;

/// Checks that artifacts can be used by all implementations.
pub trait ConsumerTest: Runnable<TestMatrix> {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>>;
    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data>;
    fn check_consumer(&self, _i: usize, _artifact: &[u8])
                      -> Result<()> {
        Ok(())
    }
    fn run(&self, implementations: &[crate::Sop]) -> Result<TestMatrix>
    {
        let mut test_results = Vec::new();

        for (i, (description, data, expectation))
            in self.produce()?.into_iter().enumerate()
        {
            let artifact = Artifact::ok(description, data);

            let mut results = Vec::new();
            for c in implementations.iter() {
                let plaintext = self.consume(i, c, &artifact.data);
                let mut a = match plaintext {
                    Ok(p) =>
                        Artifact::ok(c.version()?.to_string(), p),
                    Err(e) =>
                        Artifact::err(c.version()?.to_string(),
                                      Default::default(), &e),
                };

                if a.error.len() == 0 {
                    if let Err(e) = self.check_consumer(i, &a.data) {
                        a.error = e.to_string();
                        a.score = e.into();
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
            tags: self.tags().into_iter().map(Into::into).collect(),
            artifacts: self.artifacts(),
            consumers: implementations.iter().map(|i| i.version().unwrap())
                .collect(),
            results: test_results,
        })
    }
}

/// Checks that artifacts produced by one implementation can be used
/// by another.
pub trait ProducerConsumerTest: Runnable<TestMatrix> {
    fn produce(&self, pgp: &dyn OpenPGP) -> Result<Data>;
    fn check_producer(&self, artifact: Data) -> Result<Data> {
        Ok(artifact)
    }
    fn consume(&self,
               producer: &dyn OpenPGP,
               consumer: &dyn OpenPGP,
               artifact: &[u8]) -> Result<Data>;
    fn check_consumer(&self, _artifact: &[u8]) -> Result<()> { Ok(()) }
    fn expectation(&self) -> Option<Expectation> {
        Some(Ok("Interoperability concern.".into()))
    }
    fn run(&self, implementations: &[crate::Sop]) -> Result<TestMatrix>
    {
        let mut test_results = Vec::new();

        for p in implementations.iter() {
            let expectation = self.expectation();
            let artifact = match self.produce(p)
                .and_then(|data| self.check_producer(data))
            {
                Ok(d) => Artifact::ok(p.version()?.to_string(), d),
                Err(e) => {
                    let mut a = Artifact::err(p.version()?.to_string(),
                                              Default::default(), &e);
                    a.score = e.into();
                    a
                },
            };

            let mut results = Vec::new();
            if artifact.error.len() == 0 {
                for c in implementations.iter() {
                    let plaintext =
                        self.consume(p, c,
                                     &artifact.data);
                    let mut a = match plaintext {
                        Ok(p) =>
                            Artifact::ok(c.version()?.to_string(), p),
                        Err(e) =>
                            Artifact::err(c.version()?.to_string(),
                                          Default::default(), &e),
                    };

                    if a.error.len() == 0 {
                        if let Err(e) = self.check_consumer(&a.data) {
                            a.error = e.to_string();
                            a.score = e.into();
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
            tags: self.tags().into_iter().map(Into::into).collect(),
            artifacts: self.artifacts(),
            consumers: implementations.iter().map(|i| i.version().unwrap())
                .collect(),
            results: test_results,
        })
    }
}

/// Artifacts produced by producers.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Artifact {
    producer: String,
    data: Data,
    error: String,
    score: Score,
}

/// A score associated with an artifact.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum Score {
    Neutral,
    Success,
    Failure,
    Unsupported,
    IO,
    Unknown,
}

impl Score {
    fn hard_failure(e: &anyhow::Error) -> Option<Score> {
        if let Some(e) = e.downcast_ref::<crate::sop::ErrorWithOutput>() {
            use crate::sop::SOPError::*;
            match e.source {
                UnsupportedAsymmetricAlgo
                    | UnsupportedOption
                    | UnsupportedSubcommand
                    | UnsupportedSpecialPrefix => Some(Score::Unsupported),
                IoError(_) => Some(Score::IO),
                _ => None,
            }
        } else if let Some(_) = e.downcast_ref::<std::io::Error>() {
            Some(Score::IO)
        } else {
            Some(Score::Unknown)
        }
    }
}

impl From<anyhow::Error> for Score {
    fn from(e: anyhow::Error) -> Score {
        if let Some(e) = e.downcast_ref::<crate::sop::ErrorWithOutput>() {
            use crate::sop::SOPError::*;
            match e.source {
                UnsupportedAsymmetricAlgo
                    | UnsupportedOption
                    | UnsupportedSubcommand
                    | UnsupportedSpecialPrefix => Score::Unsupported,
                IoError(_) => Score::IO,
                _ => Score::Failure,
            }
        } else if let Some(_) = e.downcast_ref::<std::io::Error>() {
            Score::IO
        } else {
            Score::Unknown
        }
    }
}

impl Artifact {
    fn ok(producer: String, data: Data) -> Self {
        Self {
            producer,
            data,
            error: Default::default(),
            score: Score::Neutral,
        }
    }

    fn err(producer: String, data: Data, err: &anyhow::Error) -> Self {
        use std::fmt::Write;
        let mut error = String::new();
        writeln!(error, "{}", err).unwrap();
        err.chain().skip(1)
            .for_each(|cause| writeln!(error, "  because: {}", cause).unwrap());

        Self {
            producer,
            data,
            error,
            score: Score::hard_failure(err).unwrap_or(Score::Neutral),
        }
    }

    fn set_score(&mut self, expectation: &Option<Expectation>) {
        if let (Score::Neutral, Some(e)) = (&self.score, expectation) {
            self.score = if e.is_ok() == self.error.is_empty() {
                Score::Success
            } else {
                Score::Failure
            }
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct TestMatrix {
    title: String,
    slug: String,
    tags: BTreeSet<String>,
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
            let mut results = 0;
            let mut successes = 0;
            let mut failures = 0;
            let mut errors = 0;
            let mut matched_expectations = true;

            for row in &self.results {
                // Get the result corresponding to implementation
                // 'imp'.
                if let Some(r) = row.results.get(i) {
                    results += 1;

                    use Score::*;
                    match r.score {
                        Neutral => (),
                        Success => successes += 1,
                        Failure => failures += 1,
                        Unsupported | IO | Unknown => errors += 1,
                    }

                    matched_expectations &= match (&r.score, &row.expectation) {
                        (_, None) =>
                            true, // Vacuous truth, handled below.
                        (Success, Some(_)) =>
                            true, // The expectation has been checked already.
                        (Failure, Some(_)) =>
                            false, // The expectation has not been met.
                        _ => false,
                    };
                }
            }

            // If there are no expectations, we shouldn't count them
            // as being matched, as this is a vacuous truth.  Counting
            // them makes null implementations fare better than they
            // should.
            if ! self.results.iter().any(|row| row.expectation.is_some()) {
                matched_expectations = false;
            }

            // Likewise if there are no results from this implementation.
            if results == 0 {
                matched_expectations = false;
            }

            summary.add(imp.clone(), successes, failures, errors, matched_expectations);
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
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
    fn add(&mut self, imp: Version,
           successes: usize, failures: usize, errors: usize,
           matched_expectations: bool) {
        let e = self.score.entry(imp).or_default();
        e.vector_good += successes;
        e.vector_bad += failures + errors;
        if matched_expectations {
            e.test_good += 1;
        } else {
            e.test_bad += 1;
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
    vector_good: usize,
    vector_bad: usize,
    test_good: usize,
    test_bad: usize,
}

impl Ord for Scores {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.test_good.cmp(&other.test_good)
            .then(self.vector_good.cmp(&other.vector_good))
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
    use openpgp::serialize::{Serialize, stream::*};
    let mut cert = Vec::new();
    let sink = Message::new(&mut cert);
    let mut sink = Armorer::new(sink)
        .kind(openpgp::armor::Kind::PublicKey)
        .build()?;

    let mut ppr = PacketParser::from_bytes(key)?;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, ppr_) = pp.next()?;
        ppr = ppr_;
        match packet {
            Packet::SecretKey(k) =>
                Packet::PublicKey(k.parts_into_public())
                    .serialize(&mut sink)?,
            Packet::SecretSubkey(k) =>
                Packet::PublicSubkey(k.parts_into_public())
                    .serialize(&mut sink)?,
            p => p.serialize(&mut sink)?,
        }
    }
    sink.finalize()?;

    Ok(cert.into())
}

pub type TestPlan<'a> = Plan<'a, TestMatrix>;

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    asymmetric_encryption::schedule(plan)?;
    symmetric_encryption::schedule(plan)?;
    detached_signatures::schedule(plan)?;
    hashes::schedule(plan)?;
    compression::schedule(plan)?;
    key_generation::schedule(plan)?;
    certificates::schedule(plan)?;
    messages::schedule(plan)?;
    armor::schedule(plan)?;
    ecc::schedule(plan)?;
    packet_parser::schedule(plan)?;
    Ok(())
}

/// Turns a sequence of packets into an armored data stream.
pub fn make_test<T, I, P>(test: T, packets: I,
                          label: openpgp::armor::Kind,
                          expectation: Option<Expectation>)
                          -> Result<(String, Data, Option<Expectation>)>
where T: AsRef<str>,
      I: IntoIterator<Item = P>,
      P: std::borrow::Borrow<openpgp::Packet>,
{
    use openpgp::serialize::Serialize;

    let mut buf = Vec::new();
    {
        use openpgp::armor;
        let mut w =
            armor::Writer::new(&mut buf, label)?;
        for p in packets {
            p.borrow().serialize(&mut w)?;
        }
        w.finalize()?;
    }
    Ok((test.as_ref().into(), buf.into(), expectation))
}
