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

#[test]
fn telegram_ranges_cover_the_published_cidrs_and_nothing_next_to_them() {
    for ip in [
        "149.154.160.0",
        "149.154.175.255",
        "91.108.56.147",
        "91.108.59.255",
        "185.76.151.1",
        "2001:b28:f23d:f001::a",
        "2a0a:f280:ffff::1",
    ] {
        assert!(is_telegram(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "149.154.176.0",
        "149.154.159.255",
        "91.108.60.0",
        "8.8.8.8",
        "2001:b28:f23e::1",
        "2a0a:f281::1",
    ] {
        assert!(!is_telegram(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn media_addresses_seen_from_telegram_desktop_are_mapped() {
    use clap::Parser;
    let config = Config::try_parse_from(["test"]).unwrap();
    // Reported from a live Telegram Desktop session on PR #137.
    assert_eq!(
        destination_dc("149.154.165.136".parse().unwrap(), &config),
        Some(-4)
    );
    assert_eq!(
        destination_dc("91.108.56.147".parse().unwrap(), &config),
        Some(-5)
    );
}
