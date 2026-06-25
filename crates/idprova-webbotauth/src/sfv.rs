//! RFC 8941 Structured Field Values helpers.
//!
//! Wraps the `sfv` crate to provide simple serialization/deserialization
//! for the `Signature-Input` and `Signature` headers.

use super::Error;
use super::Result;
use sfv::SerializeValue;

/// Parses a Structured Field Dictionary (e.g. `Signature-Input`).
///
/// The `sfv` crate returns generic `Item` or `Dictionary` types. This wrapper
/// intends to expose the parsed data in a more ergonomic way, though for this
/// DESIGN skeleton we primarily rely on `sfv`'s internal types.
///
/// We return the underlying parsed object to avoid redefining the enum hierarchies.
pub fn parse_dictionary(input: &str) -> Result<sfv::Dictionary> {
    sfv::Parser::parse_dictionary(input.as_bytes())
        .map_err(|e| Error::InvalidStructuredField(e.to_string()))
}

/// Parses a Structured Field List (e.g. covered component list in params).
pub fn parse_list(input: &str) -> Result<sfv::List> {
    sfv::Parser::parse_list(input.as_bytes())
        .map_err(|e| Error::InvalidStructuredField(e.to_string()))
}

/// Serializes a Structured Field Dictionary to a string.
pub fn serialize_dictionary(dict: &sfv::Dictionary) -> Result<String> {
    dict.serialize_value()
        .map_err(|e| Error::InvalidStructuredField(e.to_string()))
}

/// Serializes a Structured Field List to a string.
pub fn serialize_list(list: &sfv::List) -> Result<String> {
    list.serialize_value()
        .map_err(|e| Error::InvalidStructuredField(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dictionary_roundtrip() {
        let input = r#"sig1=("@method" "@path");created=1618884473;keyid="test";alg="ed25519""#;

        let dict = parse_dictionary(input).expect("should parse");
        assert!(dict.contains_key("sig1"), "parsed dict must contain sig1");

        // Serialize, then re-parse: the key must still be present.
        // We deliberately do NOT assert exact byte equality, as sfv may
        // re-order or normalize the serialized form.
        let serialized = serialize_dictionary(&dict).expect("should serialize");
        let reparsed = parse_dictionary(&serialized).expect("should re-parse");
        assert!(
            reparsed.contains_key("sig1"),
            "re-parsed dict must still contain sig1"
        );
    }
}
