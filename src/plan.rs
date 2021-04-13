use rayon::prelude::*;

use crate::{
    Config,
    Result,
    progress_bar::ProgressBarHandle,
    tests::{
        Test,
        TestMatrix,
    },
};

/// A collection of scheduled tests.
///
/// We first collect all the tests we want to run in a plan, then
/// execute them in parallel, producing a structure describing the
/// results of the tests.
pub struct TestPlan<'a> {
    toc: Vec<(String, Vec<Box<dyn Test + Sync>>)>,
    configuration: &'a Config,
}

impl<'a> TestPlan<'a> {
    pub fn new(configuration: &'a Config) -> TestPlan<'a> {
        TestPlan {
            toc: Default::default(),
            configuration,
        }
    }

    pub fn add_section(&mut self, title: &str) {
        self.toc.push((title.into(), Vec::new()));
    }

    pub fn add(&mut self, test: Box<dyn Test + Sync>) {
        if let Some((_, entries)) = self.toc.iter_mut().last() {
            entries.push(test);
        } else {
            panic!("No section added")
        }
    }

    /// Retains only the tests specified by the predicate.
    ///
    /// Prunes empty sections.
    pub fn retain_tests<F>(&mut self, mut f: F)
    where F: FnMut(&dyn Test) -> bool,
    {
        for (_section, tests) in &mut self.toc {
            tests.retain(|t| f(t.as_ref()));
        }
        self.toc.retain(|(_section, tests)| ! tests.is_empty());
    }

    pub fn run(&self, implementations: &[crate::Sop])
               -> Result<Results>
    {
        let pb = ProgressBarHandle::new(
            self.toc.iter().map(|(_, tests)| tests.len() as u64).sum::<u64>());

        let results =
            self.toc.par_iter().map(|(section, tests)|
                                      -> Result<(String, Vec<TestMatrix>)> {
                Ok((section.into(),
                 tests.par_iter().map(
                     |test| {
                         pb.start_test(test.title());
                         let r = test.run(implementations);
                         pb.end_test();
                         r
                     }).collect::<Result<Vec<TestMatrix>>>()?))
            }).collect::<Result<Vec<(String, Vec<TestMatrix>)>>>()?;

        Ok(Results {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            timestamp: chrono::offset::Utc::now(),
            configuration: self.configuration.clone(),
            results,
        })
    }
}

/// Result of executing a TestPlan.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Results {
    pub version: String,
    pub commit: String,
    pub timestamp: chrono::DateTime<chrono::offset::Utc>,
    pub configuration: Config,
    pub results: Vec<(String, Vec<TestMatrix>)>,
}
