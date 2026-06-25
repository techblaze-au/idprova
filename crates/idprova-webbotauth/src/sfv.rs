//! RFC 8941 Structured Field Values helpers.
//!
//! Wraps the `sfv` crate to provide simple serialization/deserialization
//! for the `Signature-Input` and `Signature` headers.

use super::Result;

/// Parses a Structured Field Dictionary (e.g. `Signature-Input`).
///
/// The `sfv` crate returns generic `Item` or `Dictionary` types. This wrapper
/// intends to expose the parsed data in a more ergonomic way, though for this
/// DESIGN skeleton we primarily rely on `sfv`'s internal types.
///
/// We return the underlying parsed object to avoid redefining the enum hierarchies.
pub fn parse_dictionary(_input: &str) -> Result<sfv::Dictionary> {
    // DESIGN-ONLY: real impl parses RFC 8941 dictionaries via the sfv 0.1 `Parser`.
    todo!("parse Signature-Input/Signature dictionary via sfv")
}

/// Parses a Structured Field List (e.g. covered component list in params).
pub fn parse_list(_input: &str) -> Result<sfv::List> {
    todo!("parse structured-field list via sfv")
}

/// Serializes a Structured Field Dictionary to a string.
pub fn serialize_dictionary(_dict: &sfv::Dictionary) -> Result<String> {
    todo!("serialize dictionary via sfv SerializeValue")
}

/// Serializes a Structured Field List to a string.
pub fn serialize_list(_list: &sfv::List) -> Result<String> {
    todo!("serialize list via sfv SerializeValue")
}
