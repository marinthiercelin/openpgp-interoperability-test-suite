use std::io::Write;

use sequoia_openpgp as openpgp;

use crate::{
    Config,
    Result,
};

/// Something renderable.
pub trait Renderable {
    fn render(&self) -> Result<String>;
}

/// The test report.
#[derive(Debug, serde::Serialize)]
pub struct Report<'a> {
    version: String,
    commit: String,
    title: String,
    toc: Vec<(Entry, Vec<Entry>)>,
    body: String,
    configuration: &'a Config,
}

/// An entry in the TOC.
#[derive(Debug, serde::Serialize)]
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

impl<'a> Report<'a> {
    pub fn new(configuration: &'a Config) -> Report<'a> {
        Report {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            title: format!("OpenPGP interoperability test suite"),
            toc: Default::default(),
            body: Default::default(),
            configuration,
        }
    }

    pub fn add_section(&mut self, title: &str) -> Result<()> {
        let entry = Entry::new(title);
        self.body.push_str(&entry.render_section()?);
        self.toc.push((entry, Vec::new()));
        Ok(())
    }

    pub fn add(&mut self, result: crate::tests::TestMatrix)
               -> Result<()>
    {
        if let Some((_, entries)) = self.toc.iter_mut().last() {
            entries.push(Entry::new(&result.title()));
            self.body.push_str(&result.render()?);
            Ok(())
        } else {
            Err(failure::format_err!("No section added"))
        }
    }
}

impl<'a> Renderable for Report<'a> {
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
            32..=126 => res.push(b as char),
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
