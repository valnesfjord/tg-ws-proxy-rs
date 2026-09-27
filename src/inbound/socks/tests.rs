use super::*;

#[test]
fn unknown_destinations_warn_once_per_address_within_a_bounded_memory() {
    let first = IpAddr::from([198, 51, 100, 0]);
    assert!(first_report(first));
    assert!(!first_report(first));

    for i in 1..=REPORTED_UNKNOWN_CAP as u8 {
        assert!(first_report(IpAddr::from([198, 51, 100, i])));
    }
    assert_eq!(REPORTED_UNKNOWN.lock().unwrap().len(), REPORTED_UNKNOWN_CAP);
    // Evicted by the newer addresses, so it is reported again.
    assert!(first_report(first));
}
