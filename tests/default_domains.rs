use std::cell::Cell;
use std::time::Duration;

use tg_ws_proxy_rs::default_domains::{
    deobfuscate, fetch_default_domains_with_outbound, refetch, refetch_delays,
};
use tg_ws_proxy_rs::outbound::OutboundConnector;

mod common;

use common::{await_proxy_request, install_rustls_provider, rejecting_http_proxy};

#[test]
fn deobfuscate_restores_the_real_suffix_and_shift() {
    // Every alphabetic character in the prefix is shifted back by the number
    // of alphabetic characters it contains, and `.com` maps to `.co.uk`.
    assert_eq!(deobfuscate("virkgj.com").as_deref(), Some("pclead.co.uk"));
}

#[test]
fn deobfuscate_rejects_anything_that_is_not_a_com_domain() {
    assert!(deobfuscate("example.org").is_none());
    assert!(deobfuscate("nocomhere").is_none());
    assert!(deobfuscate("").is_none());
}

#[tokio::test]
async fn default_domain_fetch_attempts_github_through_outbound_proxy_before_fallback() {
    install_rustls_provider();

    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let domains = fetch_default_domains_with_outbound(&outbound).await;

    // The fetch went through the outbound proxy...
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT raw.githubusercontent.com:443 HTTP/1.1"));

    // ...and its failure fell back to the built-in list rather than leaving
    // the proxy with no CF domains at all.
    assert!(!domains.is_empty());
    assert!(
        domains.iter().all(|domain| domain.ends_with(".co.uk")),
        "fallback list should be deobfuscated, got {domains:?}"
    );
}

#[test]
fn refetch_backs_off_to_a_cap_and_gives_up_after_about_an_hour() {
    // #159: a boot without WAN used to leave the whole run on the built-in
    // list.  The retry has to start soon enough to catch the uplink coming up,
    // and stop once it is clear GitHub itself is what is unreachable.
    let delays: Vec<_> = refetch_delays().collect();

    assert_eq!(delays[0], Duration::from_secs(15));
    assert!(delays.windows(2).all(|w| w[1] >= w[0]));
    assert_eq!(*delays.last().unwrap(), Duration::from_secs(300));
    let total: Duration = delays.iter().sum();
    assert!(
        (Duration::from_secs(50 * 60)..=Duration::from_secs(70 * 60)).contains(&total),
        "retries span {total:?}"
    );
}

#[tokio::test]
async fn refetch_keeps_trying_until_the_list_arrives() {
    let calls = Cell::new(0);
    let fetched = refetch([Duration::from_millis(1); 5], || {
        calls.set(calls.get() + 1);
        let n = calls.get();
        async move {
            if n < 3 {
                Err("Try again".to_string())
            } else {
                Ok(vec!["pclead.co.uk".to_string()])
            }
        }
    })
    .await;

    assert_eq!(fetched, Some(vec!["pclead.co.uk".to_string()]));
    assert_eq!(calls.get(), 3, "stopped retrying once the list arrived");
}

#[tokio::test]
async fn refetch_gives_up_once_the_delays_run_out() {
    let calls = Cell::new(0);
    let fetched = refetch([Duration::from_millis(1); 3], || {
        calls.set(calls.get() + 1);
        async { Err::<Vec<String>, _>("Network unreachable".to_string()) }
    })
    .await;

    assert_eq!(fetched, None);
    assert_eq!(calls.get(), 3);
}
