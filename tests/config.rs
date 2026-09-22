use clap::Parser;
use tg_ws_proxy_rs::config::{Config, UpstreamTier};

#[test]
fn ee_secret_supplies_inbound_faketls_domain_and_key() {
    let key = "2a519e5be6c3219c69879e5fa2a0eab8";
    let domain = "www.yandex.ru";
    let secret = format!("ee{}{}", key, hex::encode(domain.as_bytes()));
    let cfg = Config::try_parse_from(["tg-ws-proxy", "--secret", &secret]).unwrap();

    assert_eq!(cfg.listen_faketls_domain().as_deref(), Some(domain));
    assert_eq!(cfg.secret_bytes(), hex::decode(key).unwrap());
    assert_eq!(cfg.link_secret(), secret);
}

#[test]
fn listen_faketls_domain_turns_plain_secret_into_ee_link() {
    let key = "2a519e5be6c3219c69879e5fa2a0eab8";
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        key,
        "--listen-faketls-domain",
        "www.yandex.ru",
    ])
    .unwrap();

    assert_eq!(cfg.secret_bytes(), hex::decode(key).unwrap());
    assert_eq!(
        cfg.link_secret(),
        format!("ee{}{}", key, hex::encode("www.yandex.ru"))
    );
}

#[test]
fn plain_secret_still_generates_dd_link() {
    let key = "2a519e5be6c3219c69879e5fa2a0eab8";
    let cfg = Config::try_parse_from(["tg-ws-proxy", "--secret", key]).unwrap();

    assert_eq!(cfg.listen_faketls_domain(), None);
    assert_eq!(cfg.link_secret(), format!("dd{}", key));
}

#[test]
fn multiple_secrets_are_parsed_and_primary_link_uses_first_secret() {
    let first = "11111111111111111111111111111111";
    let second = "22222222222222222222222222222222";
    let cfg =
        Config::try_parse_from(["tg-ws-proxy", "--secret", first, "--secret", second]).unwrap();

    assert_eq!(cfg.secrets, vec![first.to_string(), second.to_string()]);
    assert_eq!(cfg.secret_bytes(), hex::decode(first).unwrap());
    assert_eq!(
        cfg.secret_bytes_list(),
        vec![hex::decode(first).unwrap(), hex::decode(second).unwrap()]
    );
    assert_eq!(cfg.link_secret(), format!("dd{}", first));
}

#[test]
fn cf_worker_domain_accepts_python_alias_and_normalizes_url() {
    // The Python reference uses --cfproxy-worker-domain; keep that spelling
    // working while advertising the shorter Rust-style --cf-worker-domain.
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--cfproxy-worker-domain",
        "https://example.user.workers.dev/apiws",
    ])
    .unwrap()
    .with_defaults();

    assert_eq!(cfg.cf_worker_domain(), Some("example.user.workers.dev"));
}

#[test]
fn cf_worker_domains_accept_multiple_values_and_normalize() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--cf-worker-domain",
        "https://a.user.workers.dev/apiws,b.user.workers.dev/",
    ])
    .unwrap()
    .with_defaults();

    assert_eq!(
        cfg.cf_worker_domains(),
        vec![
            "a.user.workers.dev".to_string(),
            "b.user.workers.dev".to_string()
        ]
    );
}

#[test]
fn cf_disable_tls_is_opt_in() {
    let default = Config::try_parse_from(["tg-ws-proxy"]).unwrap();
    let plaintext = Config::try_parse_from(["tg-ws-proxy", "--cf-disable-tls"]).unwrap();

    assert!(!default.cf_disable_tls);
    assert!(plaintext.cf_disable_tls);
}

#[test]
fn default_host_binds_and_links_to_the_same_address() {
    // Regression test for https://github.com/valnesfjord/tg-ws-proxy-rs/issues/82:
    // without --host, the listener must bind to whatever address link_host()
    // advertises (or 127.0.0.1 if no LAN IP is detectable), never a mismatch
    // like binding 127.0.0.1 while advertising a LAN IP that isn't reachable.
    let cfg = Config::try_parse_from(["tg-ws-proxy"]).unwrap();

    let bind_host = cfg.bind_host();
    let link_host = cfg.link_host();

    if bind_host == "0.0.0.0" {
        // A LAN IP was detected: the link must show that concrete address,
        // and 0.0.0.0 actually listens on it (unlike 127.0.0.1 before this fix).
        assert_ne!(link_host, "0.0.0.0");
    } else {
        // No LAN connectivity: both must fall back to loopback consistently.
        assert_eq!(bind_host, "127.0.0.1");
        assert_eq!(link_host, "127.0.0.1");
    }
}

#[test]
fn explicit_host_is_respected_for_binding() {
    let cfg = Config::try_parse_from(["tg-ws-proxy", "--host", "127.0.0.1"]).unwrap();
    assert_eq!(cfg.bind_host(), "127.0.0.1");
}

#[test]
fn fronting_domain_is_disabled_by_default() {
    let cfg = Config::try_parse_from(["tg-ws-proxy"]).unwrap();

    assert_eq!(cfg.fronting_domain, None);
    assert_eq!(cfg.fronting_cooldown, 1800);
}

#[test]
fn fronting_flags_parse() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--fronting-domain",
        "sprinthost.ru",
        "--fronting-cooldown",
        "60",
    ])
    .unwrap();

    assert_eq!(cfg.fronting_domain.as_deref(), Some("sprinthost.ru"));
    assert_eq!(cfg.fronting_cooldown, 60);
}

#[test]
fn dd_prefixed_secret_keeps_its_link_form_and_strips_the_prefix_for_crypto() {
    let key = "2a519e5be6c3219c69879e5fa2a0eab8";
    let cfg = Config::try_parse_from(["tg-ws-proxy", "--secret", &format!("dd{key}")]).unwrap();

    assert_eq!(cfg.secret_bytes(), hex::decode(key).unwrap());
    assert_eq!(cfg.link_secret(), format!("dd{key}"));
    assert_eq!(cfg.listen_faketls_domain(), None);
}

#[test]
fn per_secret_links_are_generated_for_every_configured_secret() {
    let first = "11111111111111111111111111111111";
    let second = "22222222222222222222222222222222";
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        &format!("{first},{second}"),
        "--listen-faketls-domain",
        "www.yandex.ru",
    ])
    .unwrap();

    // Every secret gets an ee-form link for the same camouflage domain.
    let host_hex = hex::encode("www.yandex.ru");
    assert_eq!(cfg.link_secret_for(first), format!("ee{first}{host_hex}"));
    assert_eq!(cfg.link_secret_for(second), format!("ee{second}{host_hex}"));
    assert_eq!(cfg.link_secret(), cfg.link_secret_for(first));
}

#[test]
fn cf_worker_domains_drop_empty_entries() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--cf-worker-domain",
        "a.user.workers.dev,,  ,https://",
    ])
    .unwrap()
    .with_defaults();

    assert_eq!(cfg.cf_worker_domains(), vec!["a.user.workers.dev"]);
}

#[test]
fn cf_worker_domain_is_none_when_nothing_is_configured() {
    let cfg = Config::try_parse_from(["tg-ws-proxy"])
        .unwrap()
        .with_defaults();

    assert_eq!(cfg.cf_worker_domain(), None);
    assert!(cfg.cf_worker_domains().is_empty());
}

// ─── DC targets ──────────────────────────────────────────────────────────────

#[test]
fn dc_ip_flags_are_parsed_and_looked_up_individually() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--dc-ip",
        "2:149.154.167.220",
        "--dc-ip",
        "4:149.154.167.91",
    ])
    .unwrap();

    assert_eq!(cfg.dc_target_ip(2), Some("149.154.167.220"));
    assert_eq!(cfg.dc_target_ip(4), Some("149.154.167.91"));
    assert_eq!(cfg.dc_target_ip(1), None);
    // The single-DC lookup and the whole map must agree.
    assert_eq!(
        cfg.dc_redirects().get(&2).map(String::as_str),
        cfg.dc_target_ip(2)
    );
}

#[test]
fn a_repeated_dc_ip_resolves_to_the_last_one_given() {
    // The pool warms itself from `dc_redirects()` (a HashMap, so last wins)
    // while routing uses `dc_target_ip`. If the two disagreed, the pool would
    // pre-connect to one IP and the connect path use another.
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--dc-ip",
        "2:149.154.167.220",
        "--dc-ip",
        "2:149.154.167.51",
    ])
    .unwrap();

    assert_eq!(cfg.dc_target_ip(2), Some("149.154.167.51"));
    assert_eq!(
        cfg.dc_redirects().get(&2).map(String::as_str),
        cfg.dc_target_ip(2)
    );
}

#[test]
fn dc_ip_rejects_malformed_values() {
    for bad in ["2", "2:not-an-ip", "notadc:1.2.3.4", ":1.2.3.4", "2:"] {
        assert!(
            Config::try_parse_from(["tg-ws-proxy", "--dc-ip", bad]).is_err(),
            "--dc-ip {bad:?} should have been rejected"
        );
    }
}

#[test]
fn default_dc_ips_are_only_used_when_no_cf_routing_is_configured() {
    // With neither --dc-ip nor CF routing, the built-in DC 2/4 targets apply
    // so a bare `tg-ws-proxy` still works.
    let bare = Config::try_parse_from(["tg-ws-proxy"])
        .unwrap()
        .with_defaults();
    assert_eq!(bare.dc_target_ip(2), Some("149.154.167.220"));
    assert_eq!(bare.dc_target_ip(4), Some("149.154.167.220"));
    assert_eq!(bare.dc_target_ip(1), None);

    // With CF routing the defaults are dropped: CF becomes the primary path
    // for every DC, and a stale --dc-ip list would misroute it.
    let cf = Config::try_parse_from(["tg-ws-proxy", "--cf-domain", "example.net"])
        .unwrap()
        .with_defaults();
    assert_eq!(cf.dc_target_ip(2), None);

    let defaults = Config::try_parse_from(["tg-ws-proxy", "--default-domains"])
        .unwrap()
        .with_defaults();
    assert_eq!(defaults.dc_target_ip(2), None);

    // An explicit --dc-ip is never overwritten by the defaults.
    let explicit = Config::try_parse_from(["tg-ws-proxy", "--dc-ip", "3:1.2.3.4"])
        .unwrap()
        .with_defaults();
    assert_eq!(explicit.dc_target_ip(3), Some("1.2.3.4"));
    assert_eq!(explicit.dc_target_ip(2), None);
}

#[test]
fn a_random_secret_is_generated_only_when_none_was_given() {
    let generated = Config::try_parse_from(["tg-ws-proxy"])
        .unwrap()
        .with_defaults();

    assert_eq!(generated.secrets.len(), 1);
    // Must be a usable 16-byte MTProto secret, not a placeholder.
    assert_eq!(
        hex::decode(generated.primary_secret()).map(|s| s.len()),
        Ok(16)
    );
    // Two runs must not produce the same secret.
    let other = Config::try_parse_from(["tg-ws-proxy"])
        .unwrap()
        .with_defaults();
    assert_ne!(generated.primary_secret(), other.primary_secret());

    let key = "2a519e5be6c3219c69879e5fa2a0eab8";
    let explicit = Config::try_parse_from(["tg-ws-proxy", "--secret", key])
        .unwrap()
        .with_defaults();
    assert_eq!(explicit.secrets, vec![key.to_string()]);
}

#[test]
fn normalized_secrets_and_faketls_domain_reuse_startup_storage() {
    let first = "11111111111111111111111111111111";
    let second = "22222222222222222222222222222222";
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        first,
        "--secret",
        second,
        "--listen-faketls-domain",
        "www.yandex.ru",
    ])
    .unwrap()
    .with_defaults();

    let secrets = cfg.normalized_secrets();
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0], hex::decode(first).unwrap());
    assert_eq!(secrets[1], hex::decode(second).unwrap());
    assert_eq!(secrets.as_ptr(), cfg.normalized_secrets().as_ptr());

    let domain = cfg.normalized_listen_faketls_domain().unwrap();
    assert_eq!(domain, "www.yandex.ru");
    assert_eq!(
        domain.as_ptr(),
        cfg.normalized_listen_faketls_domain().unwrap().as_ptr()
    );
}

// ─── Upstream MTProto proxies ────────────────────────────────────────────────

#[test]
fn mtproto_proxy_triplets_are_parsed() {
    let secret = "00112233445566778899aabbccddeeff";
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--mtproto-proxy",
        &format!("proxy.example:443:{secret},1.2.3.4:8888:dd{secret}"),
    ])
    .unwrap();

    assert_eq!(cfg.mtproto_proxies.len(), 2);
    assert_eq!(cfg.mtproto_proxies[0].host, "proxy.example");
    assert_eq!(cfg.mtproto_proxies[0].port, 443);
    assert_eq!(cfg.mtproto_proxies[0].secret, secret);
    assert_eq!(
        cfg.mtproto_proxies[0].secret_key(),
        hex::decode(secret).unwrap()
    );
    assert_eq!(cfg.mtproto_proxies[0].faketls_hostname(), None);
    assert_eq!(cfg.mtproto_proxies[1].host, "1.2.3.4");
    assert_eq!(cfg.mtproto_proxies[1].port, 8888);
    assert_eq!(
        cfg.mtproto_proxies[1].secret_key(),
        hex::decode(secret).unwrap()
    );
}

#[test]
fn mtproto_proxy_faketls_data_is_normalized_during_parsing() {
    let key = "00112233445566778899aabbccddeeff";
    let hostname = "proxy.example";
    let secret = format!("ee{key}{}", hex::encode(hostname));
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--mtproto-proxy",
        &format!("127.0.0.1:443:{secret}"),
    ])
    .unwrap();

    let proxy = &cfg.mtproto_proxies[0];
    assert_eq!(proxy.secret_key(), hex::decode(key).unwrap());
    assert_eq!(proxy.faketls_hostname(), Some(hostname));
    assert_eq!(
        proxy.faketls_hostname().unwrap().as_ptr(),
        proxy.faketls_hostname().unwrap().as_ptr()
    );
}

#[test]
fn mtproto_proxy_rejects_malformed_triplets() {
    let secret = "00112233445566778899aabbccddeeff";
    for bad in [
        format!("proxy.example:{secret}"),
        format!("proxy.example:notaport:{secret}"),
        format!("proxy.example:99999:{secret}"),
        "proxy.example:443:nothex".to_string(),
    ] {
        assert!(
            Config::try_parse_from(["tg-ws-proxy", "--mtproto-proxy", &bad]).is_err(),
            "--mtproto-proxy {bad:?} should have been rejected"
        );
    }
}

// ─── Timeout defaults ────────────────────────────────────────────────────────

#[test]
fn timeout_and_cooldown_defaults_match_the_documented_values() {
    let cfg = Config::try_parse_from(["tg-ws-proxy"]).unwrap();

    assert_eq!(cfg.ws_connect_timeout, 10);
    assert_eq!(cfg.ws_fail_probe_timeout, 2);
    assert_eq!(cfg.ws_fail_cooldown, 30);
    assert_eq!(cfg.ws_redirect_cooldown, 300);
    assert_eq!(cfg.handshake_timeout, 10);
    assert_eq!(cfg.tcp_fallback_timeout, 10);
    assert_eq!(cfg.upstream_connect_timeout, 5);
    assert_eq!(cfg.upstream_fail_cooldown, 60);
    assert_eq!(cfg.cf_connect_timeout, 10);
    assert_eq!(cfg.cf_fail_cooldown, 60);
    assert_eq!(cfg.fronting_fail_cooldown, 60);
    assert_eq!(cfg.pool_size, 4);
    assert_eq!(cfg.pool_max_age, 55);
    assert_eq!(cfg.port, 1443);
}

#[test]
fn pinned_upstreams_parse_per_traffic_class() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--pinned-upstream",
        "cfworker,cfproxy",
        "--pinned-media-upstream",
        "tcp",
    ])
    .unwrap();

    assert_eq!(
        cfg.pinned_upstreams,
        [UpstreamTier::Cfworker, UpstreamTier::Cfproxy]
    );
    assert_eq!(cfg.pinned_media_upstreams, [UpstreamTier::Tcp]);
    assert_eq!(
        cfg.forced_upstreams(false),
        Some(&[UpstreamTier::Cfworker, UpstreamTier::Cfproxy][..])
    );
    assert_eq!(cfg.forced_upstreams(true), Some(&[UpstreamTier::Tcp][..]));
}

#[test]
fn pinned_upstreams_default_to_the_builtin_ladder() {
    let cfg = Config::try_parse_from(["tg-ws-proxy"]).unwrap();

    assert!(cfg.forced_upstreams(false).is_none());
    assert!(cfg.forced_upstreams(true).is_none());
}

#[test]
fn media_inherits_the_non_media_pin_when_not_pinned_itself() {
    let cfg = Config::try_parse_from(["tg-ws-proxy", "--pinned-upstream", "cfproxy,tcp"]).unwrap();

    assert_eq!(
        cfg.forced_upstreams(false),
        Some(&[UpstreamTier::Cfproxy, UpstreamTier::Tcp][..])
    );
    // Without its own pin, media must not silently fall back to the default
    // ladder — that would undo the egress decision the operator made.
    assert_eq!(
        cfg.forced_upstreams(true),
        Some(&[UpstreamTier::Cfproxy, UpstreamTier::Tcp][..])
    );
}

#[test]
fn a_media_pin_overrides_the_inherited_one() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--pinned-upstream",
        "cfproxy,tcp",
        "--pinned-media-upstream",
        "ws",
    ])
    .unwrap();

    assert_eq!(cfg.forced_upstreams(true), Some(&[UpstreamTier::Ws][..]));
    assert_eq!(
        cfg.forced_upstreams(false),
        Some(&[UpstreamTier::Cfproxy, UpstreamTier::Tcp][..])
    );
}

#[test]
fn legacy_cf_priority_expands_into_a_pin() {
    // --cf-priority is undocumented sugar kept for deployed configs.  Only
    // the tiers actually configured make it into the expansion — the legacy
    // flag was always a no-op for a missing tier, and pinning one would make
    // startup refuse instead.  An explicit pin is never overridden.
    let full = Config::try_parse_from([
        "tg-ws-proxy",
        "--cf-priority",
        "--cf-worker-domain",
        "w.example.dev",
        "--cf-domain",
        "cf.example.net",
        "--mtproto-proxy",
        "u.example:443:00112233445566778899aabbccddeeff",
    ])
    .unwrap()
    .with_defaults();

    let expected = [
        UpstreamTier::Cfworker,
        UpstreamTier::Cfproxy,
        UpstreamTier::Ws,
        UpstreamTier::Mtproto,
        UpstreamTier::Tcp,
    ];
    assert_eq!(full.forced_upstreams(false), Some(&expected[..]));
    assert_eq!(full.forced_upstreams(true), Some(&expected[..]));

    // The most common legacy combo: CF proxy only, no Worker / upstream.
    let cf_only = Config::try_parse_from([
        "tg-ws-proxy",
        "--cf-priority",
        "--cf-domain",
        "cf.example.net",
    ])
    .unwrap()
    .with_defaults();
    assert_eq!(
        cf_only.forced_upstreams(false),
        Some(&[UpstreamTier::Cfproxy, UpstreamTier::Ws, UpstreamTier::Tcp][..])
    );

    // Nothing CF configured at all: the flag used to be a plain no-op, so the
    // expansion must not name a tier startup would reject.
    let bare = Config::try_parse_from(["tg-ws-proxy", "--cf-priority"])
        .unwrap()
        .with_defaults();
    assert_eq!(
        bare.forced_upstreams(false),
        Some(&[UpstreamTier::Ws, UpstreamTier::Tcp][..])
    );
    assert!(bare.validate_pinned_upstreams().is_ok());

    // --default-domains alone still earns the cfproxy slot (the list arrives
    // with the startup fetch).
    let fetched = Config::try_parse_from(["tg-ws-proxy", "--cf-priority", "--default-domains"])
        .unwrap()
        .with_defaults();
    assert_eq!(
        fetched.forced_upstreams(false),
        Some(&[UpstreamTier::Cfproxy, UpstreamTier::Ws, UpstreamTier::Tcp][..])
    );

    let explicit = Config::try_parse_from([
        "tg-ws-proxy",
        "--cf-priority",
        "--pinned-upstream",
        "tcp",
        "--pinned-media-upstream",
        "ws",
    ])
    .unwrap()
    .with_defaults();
    assert_eq!(
        explicit.forced_upstreams(false),
        Some(&[UpstreamTier::Tcp][..])
    );
    assert_eq!(
        explicit.forced_upstreams(true),
        Some(&[UpstreamTier::Ws][..])
    );
}

#[test]
fn pinned_upstreams_reject_unknown_tier_names() {
    let cfg = Config::try_parse_from(["tg-ws-proxy", "--pinned-media-upstream", "bogus"]);

    assert!(cfg.is_err());
}

#[test]
fn pinned_upstream_validation_rejects_unconfigured_tiers() {
    // cfworker / cfproxy / mtproto pinned with nothing behind them must be
    // refused; each tier becomes valid once its own flag is present.
    let cases = [
        (
            "--pinned-upstream",
            "cfworker",
            "--cf-worker-domain",
            "w.example.dev",
        ),
        (
            "--pinned-upstream",
            "cfproxy",
            "--cf-domain",
            "cf.example.net",
        ),
        (
            "--pinned-media-upstream",
            "mtproto",
            "--mtproto-proxy",
            "u.example:443:00112233445566778899aabbccddeeff",
        ),
    ];
    for (pin_flag, tier, _config_flag, config_value) in cases {
        let broken = Config::try_parse_from(["tg-ws-proxy", pin_flag, tier])
            .unwrap()
            .with_defaults();
        assert!(
            broken.validate_pinned_upstreams().is_err(),
            "{tier} pin without its config must be rejected"
        );

        let fixed =
            Config::try_parse_from(["tg-ws-proxy", pin_flag, tier, _config_flag, config_value])
                .unwrap()
                .with_defaults();
        assert!(
            fixed.validate_pinned_upstreams().is_ok(),
            "{tier} pin with its config must be accepted"
        );
    }
}

#[test]
fn pinned_upstream_validation_exempts_ws_and_tcp() {
    // Whether ws is usable depends on the per-DC --dc-ip target, and tcp
    // always has the built-in fallback IP — neither can be judged at startup.
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--pinned-upstream",
        "ws",
        "--pinned-media-upstream",
        "tcp",
    ])
    .unwrap()
    .with_defaults();

    assert!(cfg.validate_pinned_upstreams().is_ok());
}

#[test]
fn link_ip_overrides_the_advertised_address() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--host",
        "0.0.0.0",
        "--link-ip",
        "203.0.113.7",
    ])
    .unwrap();

    assert_eq!(cfg.bind_host(), "0.0.0.0");
    assert_eq!(cfg.link_host(), "203.0.113.7");
}

#[test]
fn cf_worker_domains_accept_repeated_flags_including_alias() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--cf-worker-domain",
        "a.user.workers.dev",
        "--cfproxy-worker-domain",
        "b.user.workers.dev",
    ])
    .unwrap();

    assert_eq!(
        cfg.cf_worker_domains(),
        vec![
            "a.user.workers.dev".to_string(),
            "b.user.workers.dev".to_string()
        ]
    );
}

#[test]
fn version_flag_prints_the_crate_version() {
    for flag in ["--version", "-V"] {
        let err = Config::try_parse_from(["tg-ws-proxy", flag]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(
            err.to_string().contains(env!("CARGO_PKG_VERSION")),
            "{flag} output {:?} does not contain the crate version",
            err.to_string()
        );
    }
}

#[test]
fn try_from_cli_line_accepts_the_termux_flags() {
    let cfg = Config::try_from_cli_line(
        "--default-domains --host 127.0.0.1 --port 9050 --dc-ip 4:149.154.167.220 --link-ip 127.0.0.1",
    )
    .unwrap();

    assert!(cfg.default_domains);
    assert_eq!(cfg.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(cfg.port, 9050);
    assert_eq!(cfg.link_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(cfg.dc_ip, vec![(4, "149.154.167.220".to_string())]);
}

#[test]
fn try_from_cli_line_strips_a_leading_binary_name() {
    let cfg = Config::try_from_cli_line("./tg-ws --port 9050").unwrap();
    assert_eq!(cfg.port, 9050);
}

#[test]
fn try_from_cli_line_keeps_quoted_values() {
    let cfg = Config::try_from_cli_line("--host '127.0.0.1' --port \"9050\"").unwrap();
    assert_eq!(cfg.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(cfg.port, 9050);
}

#[test]
fn try_from_cli_line_rejects_unclosed_quotes() {
    let err = Config::try_from_cli_line("--host '127.0.0.1").unwrap_err();
    assert!(err.contains("unclosed quote"), "{err}");
}

#[test]
fn split_cli_args_handles_backslash_escapes() {
    let tokens = tg_ws_proxy_rs::config::split_cli_args(r#"--secret a\ b"#).unwrap();
    assert_eq!(tokens, vec!["--secret", "a b"]);
}

#[test]
fn split_cli_args_keeps_empty_quoted_tokens() {
    let tokens = tg_ws_proxy_rs::config::split_cli_args(r#"--secret "" --port 9050"#).unwrap();
    assert_eq!(tokens, vec!["--secret", "", "--port", "9050"]);
}

#[test]
fn split_cli_args_keeps_empty_quoted_single_tokens() {
    let tokens = tg_ws_proxy_rs::config::split_cli_args("''").unwrap();
    assert_eq!(tokens, vec![""]);
}

#[test]
fn split_cli_args_rejects_trailing_backslash() {
    let err = tg_ws_proxy_rs::config::split_cli_args(r"--secret abc\").unwrap_err();
    assert!(err.contains("trailing backslash"), "{err}");
}
