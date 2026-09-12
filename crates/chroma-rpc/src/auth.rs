use axum::http::StatusCode;
use subtle::ConstantTimeEq;

pub fn verify_api_key(
    headers: &axum::http::HeaderMap,
    expected: Option<&str>,
) -> Result<(), StatusCode> {
    match expected {
        Some(key) if !key.is_empty() => {
            let provided = headers
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                .ok_or(StatusCode::UNAUTHORIZED)?;
            let provided_bytes = provided.as_bytes();
            let expected_bytes = key.as_bytes();
            if provided_bytes.len() == expected_bytes.len()
                && provided_bytes.ct_eq(expected_bytes).into()
            {
                Ok(())
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Ok(()),
    }
}
