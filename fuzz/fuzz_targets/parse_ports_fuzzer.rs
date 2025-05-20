#![no_main]
use libfuzzer_sys::fuzz_target;

// Assuming parse_ports_spec is in the root of the port_watcher library
// and PortWatcherError is also accessible if needed for type context,
// though for fuzzing panics, we often just call the function.
use port_watcher::parse_ports_spec;

fuzz_target!(|data: &[u8]| {
    // Convert the byte slice to a string.
    // We use String::from_utf8_lossy to handle invalid UTF-8 sequences,
    // as parse_ports_spec expects a &str.
    let input_str = String::from_utf8_lossy(data);

    // Call the function we want to fuzz.
    // We don't need to check the result (Ok/Err) in the fuzzer itself,
    // as libFuzzer will detect crashes/panics.
    let _ = parse_ports_spec(&input_str);
});
