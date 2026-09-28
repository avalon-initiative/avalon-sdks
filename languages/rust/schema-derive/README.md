# avalon-schema-derive

`#[derive(AvalonSchema)]`: generates the `.proto` message text and the `default_visibility` /
`field_visibility` maps that an Integrator Space schema publication needs from an ordinary Rust struct.

This crate is a proc-macro dependency of [`avalon-sdk`](https://github.com/avalon-initiative/avalon-sdks/tree/main/languages/rust)
and is not used directly; the derive is re-exported as `avalon_sdk::schema::AvalonSchema`.
