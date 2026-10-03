//! Wire vocabularies that grow over time. An unknown value decodes to `Unknown` instead of failing
//! the whole response, and serializes back as the same text.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! tolerant_string_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $(#[allow(missing_docs)] $variant,)+
            /// A value this SDK version does not know, as the server sent it.
            Unknown(String),
        }

        impl $name {
            /// The wire text of this value.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Unknown(value) => value,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                match value {
                    $($text => Self::$variant,)+
                    other => Self::Unknown(other.to_string()),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Ok(Self::from(String::deserialize(deserializer)?.as_str()))
            }
        }
    };
}

tolerant_string_enum! {
    /// How a node is reachable, most preferred first.
    Connectivity {
        Direct => "direct",
        NatTraversed => "nat_traversed",
        Relayed => "relayed",
        OutboundOnly => "outbound_only",
    }
}

tolerant_string_enum! {
    /// The kind of path a measurement was taken over. A relayed measurement is never reported as
    /// direct: it includes the relay's hop.
    PathType {
        Direct => "direct",
        Traversed => "traversed",
        Relayed => "relayed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values_round_trip() {
        for (text, expected) in [
            ("direct", Connectivity::Direct),
            ("nat_traversed", Connectivity::NatTraversed),
            ("relayed", Connectivity::Relayed),
            ("outbound_only", Connectivity::OutboundOnly),
        ] {
            let json = format!("\"{text}\"");
            assert_eq!(
                serde_json::from_str::<Connectivity>(&json).unwrap(),
                expected
            );
            assert_eq!(serde_json::to_string(&expected).unwrap(), json);
        }
    }

    #[test]
    fn an_unknown_value_decodes_and_round_trips() {
        let parsed: PathType = serde_json::from_str("\"made_up\"").unwrap();
        assert_eq!(parsed, PathType::Unknown("made_up".to_string()));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"made_up\"");
        assert_eq!(parsed.to_string(), "made_up");
    }

    #[test]
    fn a_non_string_is_still_an_error() {
        assert!(serde_json::from_str::<Connectivity>("3").is_err());
    }
}
