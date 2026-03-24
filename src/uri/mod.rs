//! CMN URI parsing and URL policy utilities.
//!
//! The `cmn://` scheme follows the generic URI syntax defined in
//! [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986):
//!
//! ```text
//! cmn://domain
//! cmn://domain/hash
//! cmn://domain/mycelium/hash
//! cmn://domain/taste/hash
//! ```
//!
//! Four forms:
//! - `cmn://example.com` — domain root
//! - `cmn://example.com/b3.3yMR7vZQ9hL...` — content-addressed spore
//! - `cmn://example.com/mycelium/b3.7tRk...` — content-addressed mycelium
//! - `cmn://example.com/taste/b3.7tRk...` — content-addressed taste report

mod cmn;
mod domain;
mod url;

pub use cmn::{
    build_domain_uri, build_mycelium_uri, build_spore_uri, build_taste_uri,
    normalize_taste_target_uri, parse_uri, CmnUri, CmnUriKind,
};
pub use domain::{cmn_entry_url, validate_domain};
pub use url::{is_public_ip, normalize_and_validate_url};
