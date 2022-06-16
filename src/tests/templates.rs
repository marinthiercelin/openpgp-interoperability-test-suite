use crate::{
    Config,
    Result,
    tests::{
        Scores,
        Summary,
        TestMatrix,
    },
    plan::Results,
    templates::*,
};

/// The test results suitable for rendering.
#[derive(Debug, serde::Serialize)]
pub struct Report {
    version: String,
    commit: String,
    timestamp: chrono::DateTime<chrono::offset::Utc>,
    title: String,
    toc: Vec<(Entry, Vec<Entry>)>,
    body: String,
    summary: Vec<(String, Scores)>,
    configuration: Config,
    implementations: Vec<crate::sop::Version>,
}

impl Report {
    pub fn new(results: Results<TestMatrix>) -> Result<Report> {
        let mut toc = Vec::new();
        let mut body = String::new();
        let mut summary = Summary::default();
        for (section, section_results) in results.results {
            let section = Entry::new(&section);
            body.push_str(&section.render_section()?);

            let mut toc_section = Vec::new();
            for r in section_results {
                toc_section.push(Entry::new(&r.title()));
                body.push_str(&r.render()?);
                r.summarize(&mut summary);
            }
            toc.push((section, toc_section));
        }

        Ok(Report {
            version: results.version,
            commit: results.commit,
            timestamp: results.timestamp,
            title: format!("OpenPGP interoperability test suite"),
            toc,
            body,
            summary: summary.for_rendering(),
            configuration: results.configuration,
            implementations: results.implementations,
        })
    }
}


impl Renderable for Report {
    fn render(&self) -> Result<String> {
        use std::error::Error;
        get_tera().render("tests/report.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                anyhow::anyhow!("{}: {}", e, s)
            } else {
                anyhow::anyhow!("{}", e)
            })
    }
}

impl Renderable for crate::tests::TestMatrix {
    fn render(&self) -> Result<String> {
        use std::error::Error;
        get_tera().render("tests/test-matrix.inc.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                anyhow::anyhow!("{}: {}", e, s)
            } else {
                anyhow::anyhow!("{}", e)
            })
    }
}
