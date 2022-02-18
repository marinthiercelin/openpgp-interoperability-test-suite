use std::io::Write;

use sequoia_openpgp as openpgp;

use crate::{
    Config,
    Result,
    tests::{
        Scores,
        Summary,
    },
    plan::Results,
};

/// Something renderable.
pub trait Renderable {
    fn render(&self) -> Result<String>;
}

/// An entry in the TOC.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Entry {
    slug: String,
    title: String,
}

impl Entry {
    pub fn new(title: &str) -> Entry {
        Entry { slug: slug(title), title: title.into() }
    }

    pub fn render_section(&self) -> Result<String> {
        use std::error::Error;
        get().render("section.inc.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                anyhow::anyhow!("{}: {}", e, s)
            } else {
                anyhow::anyhow!("{}", e)
            })
    }
}

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
    pub fn new(results: Results) -> Result<Report> {
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
        get().render("report.html", self)
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
        get().render("test-matrix.inc.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                anyhow::anyhow!("{}: {}", e, s)
            } else {
                anyhow::anyhow!("{}", e)
            })
    }
}

fn get() -> &'static tera::Tera {
    lazy_static::lazy_static! {
        pub static ref TERA: tera::Tera = {
            let mut tera = tera::compile_templates!("templates/**/*");
            tera.register_filter("pgp2string", pgp2string);
            tera.register_filter("bin2string", bin2string);
            tera.register_filter("score2class", score2class);
            tera.register_filter("score_test_percentage",
                                 score_test_percentage);
            tera.register_filter("score_test_summary",
                                 score_test_summary);
            tera.register_filter("score_vector_percentage",
                                 score_vector_percentage);
            tera.register_filter("score_vector_summary",
                                 score_vector_summary);
            tera.register_function("dump_url", Box::new(dump_url));
            tera
        };
    }
    &TERA
}

/// Recovers binary data encoded in JSON.
fn json2data(v: tera::Value) -> Vec<u8> {
    use tera::Value;
    match v {
        Value::Array(v) => {
            let mut bytes = Vec::new();
            for o in v {
                match o {
                    Value::Number(n) => bytes.push(n.as_u64().unwrap() as u8),
                    _ => unimplemented!(),
                }
            }
            bytes
        },
        Value::String(s) => base64::decode(s).unwrap(),
        _ => unimplemented!(),
    }
}

fn pgp2string(v: tera::Value,
              _: std::collections::HashMap<String, tera::Value>)
              -> tera::Result<tera::Value> {
    let mut bytes = json2data(v);

    let armored = bytes.get(0).map(|b| b & 0x80 == 0).unwrap_or(false);
    if ! armored {
        let mut armored = Vec::new();
        {
            let mut writer = openpgp::armor::Writer::with_headers(
                &mut armored, openpgp::armor::Kind::File,
                Some(("Comment",
                      "ASCII Armor added by openpgp-interoperability-test-suite")))
                    .unwrap();
            writer.write_all(&bytes[..]).unwrap();
            writer.finalize().unwrap();
        }
        bytes = armored;
    }
    Ok(escape(&bytes))
}

fn bin2string(v: tera::Value,
              _: std::collections::HashMap<String, tera::Value>)
              -> tera::Result<tera::Value> {
    Ok(escape(&json2data(v)))
}

/// Escapes string for use in a HTML attribute.
///
/// Unfortunately, tera's escaping seems insufficient for that,
/// because newlines are not escaped.  Instead, we need to do the
/// escaping ourselves and use "| safe" in the template.
fn escape(bytes: &[u8]) -> tera::Value {
    let mut res = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        match b {
            32 | 33 | 35..=37 | 40..=126 => res.push(*b as char),
            _ => res.push_str(&format!("&#{};", b)),
        }
    }
    tera::Value::String(res)
}

fn score2class(v: tera::Value,
               _: std::collections::HashMap<String, tera::Value>)
               -> tera::Result<tera::Value> {
    use tera::Value;
    match v {
        Value::Null        => Ok(Value::String("score".into())),
        Value::Bool(true)  => Ok(Value::String("score-good".into())),
        Value::Bool(false) => Ok(Value::String("score-bad".into())),
        _ => unimplemented!(),
    }
}

fn score_test_percentage(v: tera::Value,
                         _: std::collections::HashMap<String, tera::Value>)
                         -> tera::Result<tera::Value> {
    let s = v.as_object()
        .expect("argument to score_test_percentage must be an object");
    let good = s.get("test_good").expect("good value missing")
        .as_f64().expect("good value not a number");
    let bad = s.get("test_bad").expect("bad value missing")
        .as_f64().expect("bad value not a number");
    Ok(format!("{:0.2}", good / (good + bad) * 100.).into())
}

fn score_test_summary(v: tera::Value,
                      _: std::collections::HashMap<String, tera::Value>)
                      -> tera::Result<tera::Value> {
    let s = v.as_object()
        .expect("argument to score_test_percentage must be an object");
    let good = s.get("test_good").expect("good value missing")
        .as_f64().expect("good value not a number");
    let bad = s.get("test_bad").expect("bad value missing")
        .as_f64().expect("bad value not a number");
    Ok(format!("{} of {}, or {:0.2}%",
               good, good + bad,
               good / (good + bad) * 100.).into())
}

fn score_vector_percentage(v: tera::Value,
                           _: std::collections::HashMap<String, tera::Value>)
                           -> tera::Result<tera::Value> {
    let s = v.as_object()
        .expect("argument to score_vector_percentage must be an object");
    let good = s.get("vector_good").expect("good value missing")
        .as_f64().expect("good value not a number");
    let bad = s.get("vector_bad").expect("bad value missing")
        .as_f64().expect("bad value not a number");
    Ok(format!("{:0.2}", good / (good + bad) * 100.).into())
}

fn score_vector_summary(v: tera::Value,
                        _: std::collections::HashMap<String, tera::Value>)
                        -> tera::Result<tera::Value> {
    let s = v.as_object()
        .expect("argument to score_vector_percentage must be an object");
    let good = s.get("vector_good").expect("good value missing")
        .as_f64().expect("good value not a number");
    let bad = s.get("vector_bad").expect("bad value missing")
        .as_f64().expect("bad value not a number");
    Ok(format!("{} of {}, or {:0.2}%",
               good, good + bad,
               good / (good + bad) * 100.).into())
}

fn dump_url(_: std::collections::HashMap<String, tera::Value>)
            -> tera::Result<tera::Value>
{
    Ok(tera::Value::String(std::env::var("DUMP_URL")
                           .unwrap_or_else(|_| {
                               "https://dump.sequoia-pgp.org".into()
                           })))
}

pub fn slug(title: &str) -> String {
    let mut slug = String::new();
    for c in title.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => slug.push(c),
            _ => slug.push('_'),
        }
    }
    slug
}
