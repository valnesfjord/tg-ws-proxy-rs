use clap::Parser;
use tg_ws_proxy_rs::config::Config;

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
fn ad_tag_is_accepted_when_valid_hex_32() {
    let cfg = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "2a519e5be6c3219c69879e5fa2a0eab8",
        "--ad-tag",
        "1234567890abcdef1234567890abcdef",
    ])
    .unwrap();

    assert_eq!(
        cfg.ad_tag.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );
}

#[test]
fn ad_tag_is_rejected_when_not_32_hex() {
    let err = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "2a519e5be6c3219c69879e5fa2a0eab8",
        "--ad-tag",
        "xyz",
    ])
    .unwrap_err();

    let msg = err.to_string();
    assert!(msg.contains("invalid ad-tag"));
}
