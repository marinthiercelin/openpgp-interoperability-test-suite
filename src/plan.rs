use rayon::prelude::*;

use crate::{
    Config,
    OpenPGP,
    Result,
    progress_bar::ProgressBarHandle,
    templates::Results,
    tests::{
        Test,
        TestMatrix,
        Summary,
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

    pub fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
               -> Result<Results<'a>>
    {
        use crate::templates::{Entry, Renderable};

        let pb = ProgressBarHandle::new(
            self.toc.iter().map(|(_, tests)| tests.len() as u64).sum::<u64>());

        let results: Vec<(Entry, Vec<Result<TestMatrix>>)> =
            self.toc.par_iter().map(|(section, tests)| {
                (Entry::new(&section),
                 tests.par_iter().map(
                     |test| {
                         pb.start_test(test.title());
                         let r = test.run(implementations);
                         pb.end_test();
                         r
                     }).collect())
            }).collect();

        let mut toc = Vec::new();
        let mut body = String::new();
        let mut summary = Summary::default();
        for (section, section_results) in results {
            body.push_str(&section.render_section()?);

            let mut toc_section = Vec::new();
            for maybe_result in section_results {
                let r = maybe_result?;
                toc_section.push(Entry::new(&r.title()));
                body.push_str(&r.render()?);
                r.summarize(&mut summary);
            }
            toc.push((section, toc_section));
        }

        Ok(Results {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            timestamp: chrono::offset::Utc::now(),
            title: format!("OpenPGP interoperability test suite"),
            toc,
            body,
            summary: summary.for_rendering(),
            configuration: self.configuration,
        })
    }
}
