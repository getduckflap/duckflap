use std::{
    collections::BTreeMap,
    io::{self, Write},
};

use serde::Serialize;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct SuccessResponse<T> {
    pub schema_version: u32,
    pub command: &'static str,
    pub ok: bool,
    pub changed: bool,
    pub data: T,
}

impl<T> SuccessResponse<T> {
    pub fn new(command: &'static str, changed: bool, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command,
            ok: true,
            changed,
            data,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub schema_version: u32,
    pub command: &'static str,
    pub ok: bool,
    pub changed: bool,
    pub error: ErrorBody,
}

impl ErrorResponse {
    pub fn new(
        command: &'static str,
        changed: bool,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command,
            ok: false,
            changed,
            error: ErrorBody {
                code,
                message: message.into(),
                remediation: None,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

#[derive(Debug, Serialize)]
pub struct Remediation {
    pub action: String,
    pub changes_allocation: bool,
}

pub fn write_json(mut writer: impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value)?;
    writeln!(writer)
}

pub fn write_posix_shell_environment(
    mut writer: impl Write,
    environment: &BTreeMap<String, String>,
) -> io::Result<()> {
    for (key, value) in environment {
        let escaped = value.replace('\'', "'\\''");
        writeln!(writer, "export {key}='{escaped}'")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use super::{ErrorResponse, SuccessResponse, write_json, write_posix_shell_environment};

    #[test]
    fn success_uses_the_versioned_envelope() {
        let response = SuccessResponse::new("status", false, json!({ "services": [] }));
        let value = serde_json::to_value(response).expect("serialize response");

        assert_eq!(
            value,
            json!({
                "schema_version": 1,
                "command": "status",
                "ok": true,
                "changed": false,
                "data": { "services": [] }
            })
        );
    }

    #[test]
    fn json_writer_terminates_the_response_with_a_newline() {
        let response = ErrorResponse::new("env", false, "NO_PROJECT", "not a project");
        let mut output = Vec::new();

        write_json(&mut output, &response).expect("write response");

        assert!(output.ends_with(b"\n"));
        let parsed: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(parsed["error"]["code"], "NO_PROJECT");
    }

    #[test]
    fn posix_shell_writer_is_sorted_and_escapes_single_quotes() {
        let environment = BTreeMap::from([
            ("SECOND".to_owned(), "two words".to_owned()),
            ("FIRST".to_owned(), "a'b".to_owned()),
        ]);
        let mut output = Vec::new();

        write_posix_shell_environment(&mut output, &environment).expect("write shell output");

        assert_eq!(
            String::from_utf8(output).expect("UTF-8 output"),
            "export FIRST='a'\\''b'\nexport SECOND='two words'\n"
        );
    }
}
