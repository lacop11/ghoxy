use crate::Result;

// Must be usable as key in HashMap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Permissions {
    scope_access_pairs: Vec<(String, String)>,
}

impl Permissions {
    pub fn from_permission_list(permissions: &[String]) -> Result<Self> {
        // TODO: Maybe do validation here? we can check against known list of permissions
        // to catch errors in config files early. would get out of sync when github adds
        // new permissions but that should be rare and not critical.

        // Use btremap, must be sorted so the result is hasheable.
        let mut scope_access_pairs = std::collections::BTreeMap::new();
        for perm in permissions {
            let parts: Vec<&str> = perm.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(crate::Error::InvalidPermission(perm.clone()));
            }
            let scope = parts[0].to_string();
            let access = parts[1].to_string();
            if scope_access_pairs.insert(scope.clone(), access).is_some() {
                return Err(crate::Error::DuplicatePermissionScope(scope));
            }
        }

        if scope_access_pairs.is_empty() {
            return Err(crate::Error::EmptyPermissions);
        }

        Ok(Permissions {
            scope_access_pairs: scope_access_pairs.into_iter().collect(),
        })
    }

    pub fn to_json_map(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (scope, access) in &self.scope_access_pairs {
            map.insert(scope.clone(), serde_json::Value::String(access.clone()));
        }
        serde_json::Value::Object(map)
    }
}
