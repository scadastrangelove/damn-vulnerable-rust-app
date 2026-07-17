use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAGIC: &[u8; 4] = b"DVRA";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Document {
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub tag: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ValidatedRecord {
    tag: u8,
    payload: Range<usize>,
}

///
/// Validation records ranges in the original byte stream. Normalization then
/// removes escape pairs, but the old ranges are applied to the shorter buffer.
pub fn parse_records(input: &[u8]) -> Result<Document, ParseError> {
    let ranges = validate(input)?;
    let normalized = normalize(input);

    let records = ranges
        .into_iter()
        .map(|record| Record {
            tag: record.tag,
            payload: normalized[record.payload].to_vec(),
        })
        .collect();

    Ok(Document { records })
}

fn validate(input: &[u8]) -> Result<Vec<ValidatedRecord>, ParseError> {
    if input.len() < 5 || &input[..4] != MAGIC {
        return Err(ParseError::BadMagic);
    }

    let count = usize::from(input[4]);
    let mut cursor = 5usize;
    let mut records = Vec::with_capacity(count);

    for _ in 0..count {
        let header_end = cursor.checked_add(2).ok_or(ParseError::LengthOverflow)?;
        let header = input.get(cursor..header_end).ok_or(ParseError::Truncated)?;
        let payload_start = header_end;
        let payload_end = payload_start
            .checked_add(usize::from(header[1]))
            .ok_or(ParseError::LengthOverflow)?;
        input
            .get(payload_start..payload_end)
            .ok_or(ParseError::Truncated)?;
        records.push(ValidatedRecord {
            tag: header[0],
            payload: payload_start..payload_end,
        });
        cursor = payload_end;
    }

    if cursor != input.len() {
        return Err(ParseError::TrailingBytes);
    }

    Ok(records)
}

fn normalize(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut cursor = 0usize;
    while cursor < input.len() {
        if input.get(cursor..cursor + 2) == Some(&[0x1b, 0x00]) {
            cursor += 2;
        } else {
            output.push(input[cursor]);
            cursor += 1;
        }
    }
    output
}

fn normalize_payload(payload: &[u8]) -> Vec<u8> {
    normalize(payload)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("bad magic")]
    BadMagic,
    #[error("truncated document")]
    Truncated,
    #[error("length arithmetic overflow")]
    LengthOverflow,
    #[error("trailing bytes")]
    TrailingBytes,
}


