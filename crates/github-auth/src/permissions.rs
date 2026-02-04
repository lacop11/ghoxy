use crate::Result;

// Must be usable as key in HashMap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Permissions {
    // TODO: list of permissions (scope:access pairs)
}

impl Permissions {
    pub fn from_permission_list(_permissions: &[String]) -> Result<Self> {
        // TODO implement
        // TODO: Maybe do validation here? we can check against known list of permissions
        // to catch errors in config files early. would get out of sync when github adds
        // new permissions but that should be rare and not critical.
        // TODO check for duplicate scopes too
        Ok(Permissions {})
    }
}
