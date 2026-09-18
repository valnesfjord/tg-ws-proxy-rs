use std::time::Duration;

use tg_ws_proxy_rs::outbound::OutboundConnector;
use tg_ws_proxy_rs::runtime::Runtime;

#[test]
fn fronting_disabled_by_default() {
    let runtime = Runtime::new(OutboundConnector::direct());

    assert_eq!(runtime.fronting_domain(), None);
    assert!(!runtime.fronting_active());
}

#[test]
fn fronting_disabled_without_a_domain_even_if_activated() {
    // `with_fronting(None, ..)` must keep the fallback off regardless of
    // what activate_fronting() does — callers gate on fronting_domain()
    // being Some before ever calling activate_fronting(), but the invariant
    // should hold even if that changes.
    let runtime =
        Runtime::new(OutboundConnector::direct()).with_fronting(None, Duration::from_secs(1800));

    assert_eq!(runtime.fronting_domain(), None);
    assert!(!runtime.fronting_active());
}

#[test]
fn activate_fronting_makes_it_active_until_cooldown_expires() {
    let runtime = Runtime::new(OutboundConnector::direct())
        .with_fronting(Some("sprinthost.ru".to_string()), Duration::from_secs(1800));

    assert!(!runtime.fronting_active());

    runtime.activate_fronting();

    assert!(runtime.fronting_active());
    assert_eq!(runtime.fronting_domain(), Some("sprinthost.ru"));
}

#[test]
fn deactivate_fronting_clears_the_sticky_window() {
    let runtime = Runtime::new(OutboundConnector::direct())
        .with_fronting(Some("sprinthost.ru".to_string()), Duration::from_secs(1800));

    runtime.activate_fronting();
    assert!(runtime.fronting_active());

    runtime.deactivate_fronting();
    assert!(!runtime.fronting_active());
    // The configured domain itself is unaffected by deactivation — only the
    // sticky window is cleared, so a later timeout can retrigger fronting.
    assert_eq!(runtime.fronting_domain(), Some("sprinthost.ru"));
}

// ─── DC metadata ─────────────────────────────────────────────────────────────

#[test]
fn websocket_dc_remaps_only_the_non_canonical_dcs() {
    let runtime = Runtime::new(OutboundConnector::direct());

    // DC 203 has no WebSocket hostname of its own and is served by DC 2.
    assert_eq!(runtime.websocket_dc(203), 2);
    for dc in 1..=5 {
        assert_eq!(runtime.websocket_dc(dc), dc);
    }
    // An unknown DC is passed through untouched rather than defaulted.
    assert_eq!(runtime.websocket_dc(42), 42);
}

#[test]
fn fallback_ip_is_known_for_every_built_in_dc() {
    let runtime = Runtime::new(OutboundConnector::direct());

    assert_eq!(runtime.fallback_ip(2), Some("149.154.167.51"));
    assert_eq!(runtime.fallback_ip(203), Some("91.105.192.100"));
    for dc in 1..=5 {
        assert!(runtime.fallback_ip(dc).is_some(), "DC{dc} has no fallback");
    }
    assert_eq!(runtime.fallback_ip(42), None);
}

#[test]
fn preferred_cf_ips_are_handed_through() {
    let ips = vec![
        "203.0.113.10".parse().unwrap(),
        "2001:db8::10".parse().unwrap(),
    ];
    let runtime = Runtime::new(OutboundConnector::direct()).with_cf_ips(ips.clone());

    assert_eq!(runtime.cf_ips(), ips);
}

#[test]
fn the_configured_outbound_connector_is_handed_through() {
    // What `summary()` renders is covered by tests/outbound.rs; here we only
    // care that Runtime hands back the connector it was built with.
    let direct = Runtime::new(OutboundConnector::direct());
    assert_eq!(direct.outbound().summary(), None);

    let proxied = Runtime::new(
        OutboundConnector::from_config(Some("socks5h://127.0.0.1:1080"), None, false).unwrap(),
    );
    assert_eq!(
        proxied.outbound().summary().as_deref(),
        Some("socks5h://127.0.0.1:1080")
    );
}

#[test]
fn zero_cooldown_expires_immediately() {
    let runtime = Runtime::new(OutboundConnector::direct())
        .with_fronting(Some("sprinthost.ru".to_string()), Duration::from_secs(0));

    runtime.activate_fronting();
    // `Instant::now() + 0 <= Instant::now()` by the time we check, so the
    // sticky window is effectively already expired.
    std::thread::sleep(Duration::from_millis(1));
    assert!(!runtime.fronting_active());
}
