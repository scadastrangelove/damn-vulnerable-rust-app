#![no_main]

use dvra_binary_parser::{normalize, parse_fast, parse_reference, validate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(validated) = validate(data) else {
        return;
    };

    let normalized = normalize(data);
    let fast = std::panic::catch_unwind(|| parse_fast(&validated, &normalized));
    let reference = parse_reference(data);

    match (fast, reference) {
        (Ok(fast), Ok(reference)) => assert_eq!(fast, reference),
        (Ok(_), Err(_)) => {}
        (Err(_), _) => panic!("fast parser panicked after raw validation"),
    }
});
