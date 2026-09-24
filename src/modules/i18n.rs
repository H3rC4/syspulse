use fluent_bundle::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use unic_langid::{langid, LanguageIdentifier};

use crate::models::Language;

static EN_FTL: &str = include_str!("../../locales/en/main.ftl");
static ES_AR_FTL: &str = include_str!("../../locales/es-AR/main.ftl");

pub struct I18n {
    bundles: std::collections::HashMap<LanguageIdentifier, FluentBundle<FluentResource>>,
    current: LanguageIdentifier,
}

// FluentBundle is not Send by default, but we only access it from the main thread.
unsafe impl Send for I18n {}

impl Default for I18n {
    fn default() -> Self {
        let mut bundles = std::collections::HashMap::new();

        let en_res = FluentResource::try_new(EN_FTL.to_string()).expect("Invalid English FTL");
        let mut en_bundle = FluentBundle::new(vec![langid!("en")]);
        en_bundle.add_resource(en_res).expect("Failed to add English resource");
        bundles.insert(langid!("en"), en_bundle);

        let es_res =
            FluentResource::try_new(ES_AR_FTL.to_string()).expect("Invalid Spanish FTL");
        let mut es_bundle = FluentBundle::new(vec![langid!("es-AR")]);
        es_bundle.add_resource(es_res).expect("Failed to add Spanish resource");
        bundles.insert(langid!("es-AR"), es_bundle);

        Self {
            bundles,
            current: langid!("en"),
        }
    }
}

impl I18n {
    pub fn set_language(&mut self, language: Language) {
        self.current = match language {
            Language::English => langid!("en"),
            Language::SpanishArgentina => langid!("es-AR"),
        };
    }

    pub fn translate(&self, key: &str) -> String {
        self.translate_with_args(key, &[])
    }

    pub fn translate_with_args(&self, key: &str, args: &[(&str, FluentValue)]) -> String {
        let bundle = self.bundles.get(&self.current).unwrap_or_else(|| {
            self.bundles
                .get(&langid!("en"))
                .expect("English bundle must exist")
        });

        let msg = match bundle.get_message(key) {
            Some(m) => m,
            None => return key.to_string(),
        };

        let pattern = match msg.value() {
            Some(p) => p,
            None => return key.to_string(),
        };

        let mut fluent_args = FluentArgs::new();
        for (k, v) in args {
            fluent_args.set(*k, v.clone());
        }

        let mut errors = Vec::new();
        let value = bundle.format_pattern(pattern, Some(&fluent_args), &mut errors);

        if errors.is_empty() {
            value.into()
        } else {
            format!("{}", value)
        }
    }
}

static GLOBAL_I18N: Lazy<Mutex<I18n>> = Lazy::new(|| Mutex::new(I18n::default()));

/// Sets the global application language.
pub fn set_global_language(language: Language) {
    if let Ok(mut i18n) = GLOBAL_I18N.lock() {
        i18n.set_language(language);
    }
}

/// Translates a key using the global language.
pub fn t(key: &str) -> String {
    if let Ok(i18n) = GLOBAL_I18N.lock() {
        i18n.translate(key)
    } else {
        key.to_string()
    }
}

/// Translates a key with arguments using the global language.
pub fn t_args(key: &str, args: &[(&str, FluentValue)]) -> String {
    if let Ok(i18n) = GLOBAL_I18N.lock() {
        i18n.translate_with_args(key, args)
    } else {
        key.to_string()
    }
}

/// Helper to build a string FluentValue.
pub fn s(value: &str) -> FluentValue<'static> {
    FluentValue::String(value.to_string().into())
}
