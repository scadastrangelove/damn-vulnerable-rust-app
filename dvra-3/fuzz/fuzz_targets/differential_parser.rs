#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let reference = dvra_parser::parse_reference(data);
    let vulnerable = dvra_parser::parse_vulnerable(data);

    match (reference, vulnerable) {
        (Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
        (Err(expected), Err(actual)) => assert_eq!(actual, expected),
        (left, right) => panic!("parser disagreement: reference={left:?}, vulnerable={right:?}"),
    }
});
