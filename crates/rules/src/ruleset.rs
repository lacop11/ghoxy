use crate::{Error, Result, Rule};
use std::collections::BTreeMap;

pub struct RuleSet {
    rules: BTreeMap<String, Rule>,
}

impl RuleSet {
    pub fn from_directory<P: AsRef<std::path::Path>>(dir: P) -> Result<Self> {
        let mut rules = BTreeMap::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(Error::InvalidRuleDirectoryEntry);
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let name = name
                .strip_suffix(".toml")
                .ok_or(Error::InvalidRuleDirectoryEntry)?;
            let rule = Rule::from_file(entry.path())?;
            // Would only happen on weird non-utf8 filenames.
            assert!(rules.insert(name.to_string(), rule).is_none());
        }
        Ok(RuleSet { rules })
    }

    pub fn get_rule(&self, name: &str) -> Option<&Rule> {
        self.rules.get(name)
    }
}
