use std::io::Write;
use rayon::prelude::*;

use sequoia_openpgp as openpgp;

use crate::{
    Config,
    OpenPGP,
    Result,
    tests::{
        Test,
        TestMatrix,
    },
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
    fn new(title: &str) -> Entry {
        Entry { slug: slug(title), title: title.into() }
    }

    fn render_section(&self) -> Result<String> {
        use std::error::Error;
        get().render("section.inc.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                failure::format_err!("{}: {}", e, s)
            } else {
                failure::format_err!("{}", e)
            })
    }
}

/// The test report.
pub struct Report<'a> {
    toc: Vec<(Entry, Vec<Box<Test + Sync>>)>,
    configuration: &'a Config,
}

impl<'a> Report<'a> {
    pub fn new(configuration: &'a Config) -> Report<'a> {
        Report {
            toc: Default::default(),
            configuration,
        }
    }

    pub fn add_section(&mut self, title: &str) {
        let entry = Entry::new(title);
        self.toc.push((entry, Vec::new()));
    }

    pub fn add(&mut self, test: Box<Test + Sync>) {
        if let Some((_, entries)) = self.toc.iter_mut().last() {
            entries.push(test);
        } else {
            panic!("No section added")
        }
    }

    pub fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
               -> Result<Results<'a>>
    {
        let pb = ProgressBarHandle::new(
            self.toc.iter().map(|(_, tests)| tests.len() as u64).sum::<u64>());

        let results: Vec<(Entry, Vec<Result<TestMatrix>>)> =
            self.toc.par_iter().map(|(section, tests)| {
                (section.clone(),
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
        for (section, section_results) in results {
            body.push_str(&section.render_section()?);

            let mut toc_section = Vec::new();
            for maybe_result in section_results {
                let r = maybe_result?;
                toc_section.push(Entry::new(&r.title()));
                body.push_str(&r.render()?);
            }
            toc.push((section, toc_section));
        }

        Ok(Results {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            title: format!("OpenPGP interoperability test suite"),
            toc,
            body,
            configuration: self.configuration,
        })
    }
}

/// The test results.
#[derive(Debug, serde::Serialize)]
pub struct Results<'a> {
    version: String,
    commit: String,
    title: String,
    toc: Vec<(Entry, Vec<Entry>)>,
    body: String,
    configuration: &'a Config,
}


impl<'a> Renderable for Results<'a> {
    fn render(&self) -> Result<String> {
        use std::error::Error;
        get().render("results.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                failure::format_err!("{}: {}", e, s)
            } else {
                failure::format_err!("{}", e)
            })
    }
}

impl Renderable for crate::tests::TestMatrix {
    fn render(&self) -> Result<String> {
        use std::error::Error;
        get().render("test-matrix.inc.html", self)
            .map_err(|e| if let Some(s) = e.source() {
                failure::format_err!("{}: {}", e, s)
            } else {
                failure::format_err!("{}", e)
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

fn pgp2string(v: tera::Value,
              _: std::collections::HashMap<String, tera::Value>)
              -> tera::Result<tera::Value> {
    use tera::Value;
    let mut bytes: Vec<u8> = Vec::new();
    match v {
        Value::Array(v) => {
            for o in v {
                match o {
                    Value::Number(n) => bytes.push(n.as_u64().unwrap() as u8),
                    _ => unimplemented!(),
                }
            }
        },
        _ => unimplemented!(),
    }
    let armored = bytes.get(0).map(|b| b & 0x80 == 0).unwrap_or(false);
    if ! armored {
        let mut armored = Vec::new();
        {
            let mut writer = openpgp::armor::Writer::new(
                &mut armored, openpgp::armor::Kind::File,
                &[("Comment",
                   "ASCII Armor added by openpgp-interoperability-test-suite")])
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
    let mut bytes: Vec<u8> = Vec::new();
    match v {
        Value::Array(v) => {
            for o in v {
                match o {
                    Value::Number(n) => bytes.push(n.as_u64().unwrap() as u8),
                    _ => unimplemented!(),
                }
            }
        },
        _ => unimplemented!(),
    }


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

// Progress bar support
//
// This is a bit awkward, we cannot use indicatif's rayon support
// directly, because we nest par_iter().

use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender};
use std::thread;

struct ProgressBarHandle {
    ch: Mutex<Sender<Option<String>>>,
}

impl ProgressBarHandle {
    fn new(length: u64) -> ProgressBarHandle {
        let pb = indicatif::ProgressBar::new(length);
        let (sender, receiver) = channel();

        thread::spawn(move || {
            eprintln!("Running tests:");
            for msg in receiver.iter() {
                if let Some(m) = msg {
                    pb.println(format!("  - {}", m));
                } else {
                    pb.inc(1);
                }
            }
        });

        ProgressBarHandle {
            ch: Mutex::new(sender),
        }
    }

    fn start_test(&self, title: String) {
        self.ch.lock().unwrap().send(Some(title)).unwrap();
    }

    fn end_test(&self) {
        self.ch.lock().unwrap().send(None).unwrap();
    }
}
