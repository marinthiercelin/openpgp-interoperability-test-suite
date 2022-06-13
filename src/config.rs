use std::collections::HashMap;

use anyhow::Context;

use crate::{
    Result,
};

/// Maximum size of artifacts included in the results.
pub const MAXIMUM_ARTIFACT_SIZE: usize = 50_000;

/// Test suite configuration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    drivers: Vec<Driver>,
    #[serde(default)]
    rlimits: std::collections::HashMap<String, u64>,
}

/// A driver configuration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Driver {
    path: String,
    #[serde(default)]
    env: std::collections::HashMap<String, String>,
}

impl Config {
    pub fn set_rlimits(&self) -> Result<()> {
        for (key, &value) in self.rlimits.iter() {
            match key.as_str() {
                "DATA" => rlimit::RLimit::DATA.set(value, value)?,
                _ => return
                    Err(anyhow::anyhow!("Unknown limit {:?}", key)),
            }
        }
        Ok(())
    }

    pub fn implementations(&self, env_override: HashMap<String, String>)
                           -> Result<Vec<crate::Sop>>
    {
        let mut r: Vec<crate::Sop> = Vec::new();
        for d in self.drivers.iter() {
            let mut env = d.env.clone();
            for (k, v) in env_override.iter() {
                env.insert(k.into(), v.into());
            }
            r.push(crate::sop::Sop::with_env(&d.path, env)
                   .context("Creating sop backend")?);
        }
        Ok(r)
    }
}
