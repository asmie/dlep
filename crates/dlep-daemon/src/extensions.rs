//! Startup recipes for configured extension instances.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use dlep_ext::{DlepExtension, ExtensionRegistry};
use thiserror::Error;

/// Settings for one plugin. The plugin owns validation of its complete table.
pub type ExtensionConfig = toml::Table;
/// TOML `[extensions.NAME]` tables, keyed by registered factory name.
pub type ExtensionsConfig = BTreeMap<String, ExtensionConfig>;
type Factory = dyn Fn(&ExtensionConfig) -> Result<Arc<dyn DlepExtension>, String> + Send + Sync;

#[derive(Clone)]
enum Registration {
    Instance(Arc<dyn DlepExtension>),
    Factory { name: String, create: Arc<Factory> },
}

/// Ordered plugin recipes. Clones share factories and prebuilt instances;
/// each build invokes the factories again. Registration names and unused
/// settings tables are checked before invoking any factory. Factories validate
/// their settings and run once per build, including configuration checks. They
/// should construct local plugin state without starting session work.
#[derive(Clone, Default)]
pub struct ExtensionCatalog {
    registrations: Vec<Registration>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExtensionSetupError {
    #[error("extension factory name must not be empty")]
    EmptyName,
    #[error("extension factory {name:?} is registered more than once")]
    DuplicateFactory { name: String },
    #[error("settings for extension {name:?} have no registered factory")]
    UnknownFactory { name: String },
    #[error("extension {name:?} configuration failed: {message}")]
    Factory { name: String, message: String },
}

impl ExtensionCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a prebuilt instance, retaining the existing extension API.
    pub fn register(&mut self, extension: Arc<dyn DlepExtension>) {
        self.registrations.push(Registration::Instance(extension));
    }

    /// Register a named factory. It receives an empty table when no settings
    /// were supplied. All registrations retain their insertion order.
    pub fn register_factory(
        &mut self,
        name: impl Into<String>,
        create: impl Fn(&ExtensionConfig) -> Result<Arc<dyn DlepExtension>, String>
        + Send
        + Sync
        + 'static,
    ) {
        self.registrations.push(Registration::Factory {
            name: name.into(),
            create: Arc::new(create),
        });
    }

    pub fn build(
        &self,
        settings: &ExtensionsConfig,
    ) -> Result<ExtensionRegistry, ExtensionSetupError> {
        let mut names = BTreeSet::new();
        for registration in &self.registrations {
            if let Registration::Factory { name, .. } = registration {
                if name.is_empty() {
                    return Err(ExtensionSetupError::EmptyName);
                }
                if !names.insert(name.as_str()) {
                    return Err(ExtensionSetupError::DuplicateFactory { name: name.clone() });
                }
            }
        }
        for name in settings.keys() {
            if !names.contains(name.as_str()) {
                return Err(ExtensionSetupError::UnknownFactory { name: name.clone() });
            }
        }
        let empty = ExtensionConfig::new();
        let mut registry = ExtensionRegistry::new();
        for registration in &self.registrations {
            let extension = match registration {
                Registration::Instance(extension) => extension.clone(),
                Registration::Factory { name, create } => {
                    create(settings.get(name).unwrap_or(&empty)).map_err(|message| {
                        ExtensionSetupError::Factory {
                            name: name.clone(),
                            message,
                        }
                    })?
                }
            };
            registry.register(extension);
        }
        Ok(registry)
    }
}
