use tg_ws_proxy_rs::outbound::OutboundConnector;
use tg_ws_proxy_rs::runtime::Runtime;

#[test]
fn fronting_disabled_by_default() {
    let runtime = Runtime::new(OutboundConnector::direct());

    assert_eq!(runtime.fronting_domain(), None);
}

#[test]
fn fronting_domain_is_a_plain_configuration_field() {
    // #111: fronting is unconditional while the domain is set — there is no
    // sticky window or activation state left to get wrong, so the getter is
    // the whole contract.
    let runtime =
        Runtime::new(OutboundConnector::direct()).with_fronting(Some("sprinthost.ru".to_string()));

    assert_eq!(runtime.fronting_domain(), Some("sprinthost.ru"));

    let runtime = Runtime::new(OutboundConnector::direct()).with_fronting(None);

    assert_eq!(runtime.fronting_domain(), None);
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
