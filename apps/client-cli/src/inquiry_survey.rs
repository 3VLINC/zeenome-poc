//! Validate optional patient questionnaire answers against JSON Schema stored in `jobs.constraints`.

use jsonschema::validator_for;
use serde_json::Value;
use zeenome_core::errors::{Result, ZeenomeError};

pub const SURVEY_ANSWER_SIZE_LIMIT_BYTES: usize = 96 * 1024;

#[derive(Debug, Clone)]
pub struct InquirySurveyConfig {
    pub json_schema: Value,
    pub require_answers: bool,
}

/// Extract `DemoJobConstraints.inquirySurveyV1` from job constraints blob.
pub fn parse_inquiry_survey(constraints: &Option<Value>) -> Option<InquirySurveyConfig> {
    let c = constraints.as_ref()?;
    let obj = c.as_object()?;
    let survey = obj.get("inquirySurveyV1")?;
    let survey_obj = survey.as_object()?;
    if survey_obj.get("schemaVersion")?.as_u64()? != 1 {
        return None;
    }
    let require = survey_obj.get("requireAnswers")?.as_bool()?;
    let json_schema = survey_obj.get("jsonSchema").cloned()?;
    if !json_schema.is_object() {
        return None;
    }
    Some(InquirySurveyConfig {
        json_schema,
        require_answers: require,
    })
}

fn nonempty_object_payload(v: &Value) -> bool {
    matches!(v, Value::Object(m) if !m.is_empty())
}

pub fn validate_survey_answers(
    config: Option<&InquirySurveyConfig>,
    answers: Option<&Value>,
) -> Result<Option<Value>> {
    let Some(cfg) = config else {
        if answers.map(nonempty_object_payload).unwrap_or(false) {
            return Err(ZeenomeError::InvalidFormat(
                "This job has no questionnaire; do not attach survey answers".to_string(),
            ));
        }
        return Ok(None);
    };

    let instance = match answers {
        Some(v) if !v.is_null() => v.clone(),
        _ => Value::Object(Default::default()),
    };

    let bytes = serde_json::to_vec(&instance).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("survey answers JSON encode error: {e}"))
    })?;
    if bytes.len() > SURVEY_ANSWER_SIZE_LIMIT_BYTES {
        return Err(ZeenomeError::InvalidFormat(format!(
            "survey answers exceed {} bytes",
            SURVEY_ANSWER_SIZE_LIMIT_BYTES
        )));
    }

    if !instance.is_object() {
        return Err(ZeenomeError::InvalidFormat(
            "survey answers must be a JSON object".to_string(),
        ));
    }

    if cfg.require_answers {
        let root = cfg
            .json_schema
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if root != "object" {
            return Err(ZeenomeError::InvalidFormat(
                "job survey jsonSchema root must have type \"object\"".to_string(),
            ));
        }

        let validator = validator_for(&cfg.json_schema).map_err(|e| {
            ZeenomeError::InvalidFormat(format!("invalid job survey JSON Schema: {e}"))
        })?;

        validator.validate(&instance).map_err(|e| {
            ZeenomeError::InvalidFormat(format!("survey answers failed validation: {e}"))
        })?;

        Ok(Some(instance))
    } else if answers.map(nonempty_object_payload).unwrap_or(false) {
        // Optional survey: validate when the patient sends a non-empty object.
        let root = cfg
            .json_schema
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if root != "object" {
            return Err(ZeenomeError::InvalidFormat(
                "job survey jsonSchema root must have type \"object\"".to_string(),
            ));
        }
        let validator = validator_for(&cfg.json_schema).map_err(|e| {
            ZeenomeError::InvalidFormat(format!("invalid job survey JSON Schema: {e}"))
        })?;
        validator.validate(&instance).map_err(|e| {
            ZeenomeError::InvalidFormat(format!("survey answers failed validation: {e}"))
        })?;
        Ok(Some(instance))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_inquiry_survey, validate_survey_answers, SURVEY_ANSWER_SIZE_LIMIT_BYTES};
    use serde_json::json;
    use zeenome_core::errors::ZeenomeError;

    #[test]
    fn parse_inquiry_survey_accepts_valid_v1_config() {
        let constraints = Some(json!({
            "inquirySurveyV1": {
                "schemaVersion": 1,
                "requireAnswers": true,
                "jsonSchema": {
                    "type": "object",
                    "properties": { "age": { "type": "integer" } },
                    "required": ["age"]
                }
            }
        }));

        let cfg = parse_inquiry_survey(&constraints).expect("expected survey config");
        assert!(cfg.require_answers);
        assert_eq!(cfg.json_schema["type"], "object");
    }

    #[test]
    fn parse_inquiry_survey_rejects_non_v1_config() {
        let constraints = Some(json!({
            "inquirySurveyV1": {
                "schemaVersion": 2,
                "requireAnswers": true,
                "jsonSchema": { "type": "object" }
            }
        }));

        assert!(parse_inquiry_survey(&constraints).is_none());
    }

    #[test]
    fn validate_requires_schema_match_when_answers_are_required() {
        let constraints = Some(json!({
            "inquirySurveyV1": {
                "schemaVersion": 1,
                "requireAnswers": true,
                "jsonSchema": {
                    "type": "object",
                    "properties": { "age": { "type": "integer" } },
                    "required": ["age"]
                }
            }
        }));
        let cfg = parse_inquiry_survey(&constraints).expect("config");

        let validated =
            validate_survey_answers(Some(&cfg), Some(&json!({ "age": 37 }))).expect("valid");
        assert_eq!(validated, Some(json!({ "age": 37 })));
    }

    #[test]
    fn validate_rejects_answers_when_job_has_no_questionnaire() {
        let err = validate_survey_answers(None, Some(&json!({ "foo": "bar" })))
            .expect_err("answers should be rejected");
        assert!(matches!(err, ZeenomeError::InvalidFormat(msg) if msg.contains("no questionnaire")));
    }

    #[test]
    fn validate_optional_survey_allows_empty_answers() {
        let constraints = Some(json!({
            "inquirySurveyV1": {
                "schemaVersion": 1,
                "requireAnswers": false,
                "jsonSchema": {
                    "type": "object",
                    "properties": { "notes": { "type": "string" } }
                }
            }
        }));
        let cfg = parse_inquiry_survey(&constraints).expect("config");

        let validated = validate_survey_answers(Some(&cfg), None).expect("should be optional");
        assert!(validated.is_none());
    }

    #[test]
    fn validate_rejects_payloads_larger_than_limit() {
        let constraints = Some(json!({
            "inquirySurveyV1": {
                "schemaVersion": 1,
                "requireAnswers": true,
                "jsonSchema": {
                    "type": "object",
                    "properties": { "blob": { "type": "string" } },
                    "required": ["blob"]
                }
            }
        }));
        let cfg = parse_inquiry_survey(&constraints).expect("config");
        let large_blob = "x".repeat(SURVEY_ANSWER_SIZE_LIMIT_BYTES + 1);
        let err = validate_survey_answers(Some(&cfg), Some(&json!({ "blob": large_blob })))
            .expect_err("payload should exceed byte limit");
        assert!(matches!(err, ZeenomeError::InvalidFormat(msg) if msg.contains("exceed")));
    }
}
