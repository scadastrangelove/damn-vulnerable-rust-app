//! Two parsers for a tiny artifact envelope.
//!
//! The fast path intentionally validates offsets before normalization. The
//! reference path normalizes first and is the differential oracle.

use std::{error::Error, fmt, slice};

const HEADER: &[u8] = b"DVRA|";
const LENGTH_MARKER: &[u8] = b"|len=";
const DATA_MARKER: &[u8] = b"|data=";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedEnvelope {
    data_start: usize,
    data_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    BadHeader,
    MissingLength,
    MissingData,
    InvalidLength,
    Truncated,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BadHeader => "invalid DVRA envelope header",
            Self::MissingLength => "missing length field",
            Self::MissingData => "missing data field",
            Self::InvalidLength => "invalid decimal length",
            Self::Truncated => "truncated data field",
        };
        formatter.write_str(message)
    }
}

impl Error for ParseError {}

pub fn validate(input: &[u8]) -> Result<ValidatedEnvelope, ParseError> {
    if !input.starts_with(HEADER) {
        return Err(ParseError::BadHeader);
    }

    let length_marker = find_subslice(input, LENGTH_MARKER).ok_or(ParseError::MissingLength)?;
    let data_marker = find_subslice(input, DATA_MARKER).ok_or(ParseError::MissingData)?;
    let length_start = length_marker + LENGTH_MARKER.len();
    if data_marker <= length_start {
        return Err(ParseError::InvalidLength);
    }

    let data_len = std::str::from_utf8(&input[length_start..data_marker])
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(ParseError::InvalidLength)?;
    let data_start = data_marker + DATA_MARKER.len();
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(ParseError::Truncated)?;
    if data_end > input.len() {
        return Err(ParseError::Truncated);
    }

    Ok(ValidatedEnvelope {
        data_start,
        data_len,
    })
}

/// Removes escape bytes before delimiters and backslashes.
#[must_use]
pub fn normalize(input: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        if input[cursor] == b'\\' && cursor + 1 < input.len() {
            normalized.push(input[cursor + 1]);
            cursor += 2;
        } else {
            normalized.push(input[cursor]);
            cursor += 1;
        }
    }
    normalized
}

/// Fast parser used by the worker.
///
/// It trusts offsets that were calculated for the pre-normalized input.
#[must_use]
pub fn parse_fast(validated: &ValidatedEnvelope, normalized: &[u8]) -> Vec<u8> {
    let data_end = validated.data_start + validated.data_len;
    normalized[validated.data_start..data_end].to_vec()
}

pub fn parse_reference(input: &[u8]) -> Result<Vec<u8>, ParseError> {
    let normalized = normalize(input);
    let validated = validate(&normalized)?;
    Ok(parse_fast(&validated, &normalized))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRecord {
    pub tag: u8,
    pub payload: Vec<u8>,
}

/// Decoder retained for a legacy route that is never registered by the API.
///
/// The input contract is not checked before raw pointer reads.
#[must_use]
pub fn legacy_decode(input: &[u8]) -> LegacyRecord {
    // SAFETY: This is intentionally unsound lab code. Its caller-visible
    // preconditions are neither expressed nor checked.
    let tag = unsafe { *input.get_unchecked(0) };
    // SAFETY: Same intentionally missing length precondition as above.
    let payload_len = unsafe { *input.get_unchecked(1) } as usize;
    // SAFETY: `payload_len` is trusted even when it extends beyond `input`.
    let payload = unsafe { slice::from_raw_parts(input.as_ptr().add(2), payload_len) }.to_vec();
    LegacyRecord { tag, payload }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{legacy_decode, normalize, parse_fast, parse_reference, validate};

    const CRASHING_FIXTURE: &[u8] = b"DVRA|name=a\\|b|len=4|data=WXYZ";

    #[test]
    fn reference_parser_handles_escaped_delimiter() {
        assert_eq!(
            parse_reference(CRASHING_FIXTURE).expect("reference parse"),
            b"WXYZ"
        );
    }

    #[test]
    #[should_panic]
    fn dvra_006_stale_offsets_panic_after_normalization() {
        let validated = validate(CRASHING_FIXTURE).expect("valid raw envelope");
        let normalized = normalize(CRASHING_FIXTURE);
        let _ = parse_fast(&validated, &normalized);
    }

    #[test]
    fn legacy_decoder_accepts_its_implicit_contract() {
        let record = legacy_decode(&[7, 3, b'a', b'b', b'c']);
        assert_eq!(record.tag, 7);
        assert_eq!(record.payload, b"abc");
    }

    #[cfg(miri)]
    #[test]
    fn dvra_013_miri_reaches_the_unregistered_decoder_directly() {
        let _ = legacy_decode(&[]);
    }
}
