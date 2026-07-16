use std::{
    fs,
    io,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

const MAGIC: &[u8; 4] = b"DVB1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    pub path: String,
    pub contents: Vec<u8>,
}

/// Parse the compact training bundle format.
///
/// Layout: `DVB1`, one-byte entry count, then for every entry a one-byte path
/// length, UTF-8 path bytes, a big-endian `u16` content length, and content.
pub fn parse(input: &[u8]) -> Result<Vec<BundleEntry>, BundleError> {
    if input.len() < 5 || &input[..4] != MAGIC {
        return Err(BundleError::BadMagic);
    }

    let count = usize::from(input[4]);
    let mut cursor = 5usize;
    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        let path_len = usize::from(*input.get(cursor).ok_or(BundleError::Truncated)?);
        cursor = cursor.checked_add(1).ok_or(BundleError::LengthOverflow)?;

        let path_end = cursor
            .checked_add(path_len)
            .ok_or(BundleError::LengthOverflow)?;
        let path_bytes = input.get(cursor..path_end).ok_or(BundleError::Truncated)?;
        let path = std::str::from_utf8(path_bytes)
            .map_err(BundleError::InvalidUtf8)?
            .to_owned();
        cursor = path_end;

        let length_end = cursor.checked_add(2).ok_or(BundleError::LengthOverflow)?;
        let length_bytes: [u8; 2] = input
            .get(cursor..length_end)
            .ok_or(BundleError::Truncated)?
            .try_into()
            .expect("slice length was checked");
        let content_len = usize::from(u16::from_be_bytes(length_bytes));
        cursor = length_end;

        let content_end = cursor
            .checked_add(content_len)
            .ok_or(BundleError::LengthOverflow)?;
        let contents = input
            .get(cursor..content_end)
            .ok_or(BundleError::Truncated)?
            .to_vec();
        cursor = content_end;

        entries.push(BundleEntry { path, contents });
    }

    if cursor != input.len() {
        return Err(BundleError::TrailingBytes);
    }

    Ok(entries)
}

/// DVRA-008: writes archive-controlled paths below `destination` without
/// validating whether `join` escapes the intended extraction directory.
pub fn extract_vulnerable(
    input: &[u8],
    destination: &Path,
) -> Result<Vec<PathBuf>, BundleError> {
    let entries = parse(input)?;
    let mut written = Vec::with_capacity(entries.len());

    for entry in entries {
        let output = destination.join(entry.path);
        write_entry(&output, &entry.contents)?;
        written.push(output);
    }

    Ok(written)
}

/// Rejects absolute paths, parent traversal, platform prefixes, and all other
/// components except ordinary relative path segments.
pub fn extract_fixed(input: &[u8], destination: &Path) -> Result<Vec<PathBuf>, BundleError> {
    let entries = parse(input)?;

    for entry in &entries {
        validate_relative_path(Path::new(&entry.path))?;
    }

    let mut written = Vec::with_capacity(entries.len());
    for entry in entries {
        let output = destination.join(entry.path);
        write_entry(&output, &entry.contents)?;
        written.push(output);
    }

    Ok(written)
}

fn validate_relative_path(path: &Path) -> Result<(), BundleError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(BundleError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn write_entry(path: &Path, contents: &[u8]) -> Result<(), BundleError> {
    let parent = path.parent().ok_or_else(|| BundleError::UnsafePath(path.to_owned()))?;
    fs::create_dir_all(parent).map_err(|source| BundleError::Write {
        path: parent.to_owned(),
        source,
    })?;
    fs::write(path, contents).map_err(|source| BundleError::Write {
        path: path.to_owned(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("bad bundle magic")]
    BadMagic,
    #[error("truncated bundle")]
    Truncated,
    #[error("bundle length arithmetic overflow")]
    LengthOverflow,
    #[error("bundle path is not valid UTF-8: {0}")]
    InvalidUtf8(std::str::Utf8Error),
    #[error("bundle contains trailing bytes")]
    TrailingBytes,
    #[error("unsafe bundle path: {}", .0.display())]
    UnsafePath(PathBuf),
    #[error("failed to write {}: {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{BundleError, extract_fixed, extract_vulnerable, parse};

    fn bundle(path: &str, contents: &[u8]) -> Vec<u8> {
        let path_len = u8::try_from(path.len()).expect("test path fits");
        let contents_len = u16::try_from(contents.len()).expect("test contents fit");
        let mut bytes = b"DVB1\x01".to_vec();
        bytes.push(path_len);
        bytes.extend_from_slice(path.as_bytes());
        bytes.extend_from_slice(&contents_len.to_be_bytes());
        bytes.extend_from_slice(contents);
        bytes
    }

    fn sandbox() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        std::env::temp_dir().join(format!("dvra-bundle-{}-{nonce}", std::process::id()))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn parser_reads_one_entry() {
        let entries = parse(&bundle("report.txt", b"hello")).expect("valid bundle");
        assert_eq!(entries[0].path, "report.txt");
        assert_eq!(entries[0].contents, b"hello");
    }

    #[test]
    fn vulnerable_extractor_escapes_job_directory() {
        let sandbox = sandbox();
        let job = sandbox.join("storage/job-8");
        let escaped = sandbox.join("storage/other-job.txt");
        let input = bundle("../other-job.txt", b"overwritten");

        extract_vulnerable(&input, &job).expect("vulnerable extraction succeeds");
        assert_eq!(fs::read(&escaped).expect("escaped file"), b"overwritten");
        cleanup(&sandbox);
    }

    #[test]
    fn fixed_extractor_rejects_parent_component_before_writing() {
        let sandbox = sandbox();
        let job = sandbox.join("storage/job-8");
        let escaped = sandbox.join("storage/other-job.txt");
        let input = bundle("../other-job.txt", b"overwritten");

        let error = extract_fixed(&input, &job).expect_err("path should be rejected");
        assert!(matches!(error, BundleError::UnsafePath(_)));
        assert!(!escaped.exists());
        cleanup(&sandbox);
    }
}
