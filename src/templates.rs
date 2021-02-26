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
pub struct Report<'a> {
    version: String,
    commit: String,
    timestamp: chrono::DateTime<chrono::offset::Utc>,
    title: String,
    toc: Vec<(Entry, Vec<Entry>)>,
    body: String,
    summary: Vec<(String, Scores)>,
    configuration: &'a Config,
}

impl<'a> Report<'a> {
    pub fn new(results: Results<'a>) -> Result<Report<'a>> {
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
        })
    }
}


impl<'a> Renderable for Report<'a> {
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
    use tera::Value;
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
    let mut res = String::new();
    for b in bytes {
        match b {
            32..=126 => res.push(b as char),
            _ => res.push_str(&format!("&#{};", b)),
        }
    }
    Ok(Value::String(res))
}

fn bin2string(v: tera::Value,
              _: std::collections::HashMap<String, tera::Value>)
              -> tera::Result<tera::Value> {
    use tera::Value;
    let bytes = json2data(v);

    let mut res = String::new();
    for b in bytes {
        match b {
            32 | 33 | 35..=38 | 40..=126 => res.push(b as char),
            _ => res.push_str(&format!("&#{};", b)),
        }
    }
    Ok(Value::String(res))
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
