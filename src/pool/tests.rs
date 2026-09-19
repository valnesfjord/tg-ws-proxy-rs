use super::*;

#[test]
fn direct_refill_is_reserved_before_a_task_can_be_spawned() {
    let pool = WsPool::new(4, Duration::from_secs(60));
    let key = (2, true);

    assert!(pool.reserve_refill(key));
    for _ in 0..1_000 {
        assert!(!pool.reserve_refill(key));
    }
    assert_eq!(pool.refilling.lock().unwrap().len(), 1);
}

#[test]
fn cloudflare_refill_is_reserved_before_a_task_can_be_spawned() {
    let pool = WsPool::new(4, Duration::from_secs(60));
    let key = (CfTier::Worker, 2, true);

    assert!(pool.reserve_cf_refill(key));
    for _ in 0..1_000 {
        assert!(!pool.reserve_cf_refill(key));
    }
    assert_eq!(pool.cf_refilling.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_direct_miss_burst_spawns_one_refill_task() {
    let pool = Arc::new(WsPool::new(4, Duration::from_secs(60)));

    for _ in 0..1_000 {
        pool.schedule_refill(2, true, "203.0.113.10", false);
    }

    assert_eq!(pool.refill_task_spawns.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_cloudflare_prefetch_burst_spawns_one_refill_task() {
    let pool = Arc::new(WsPool::new(4, Duration::from_secs(60)));

    for _ in 0..1_000 {
        pool.cf_prefetch(CfTarget {
            tier: CfTier::Worker,
            dc: 2,
            is_media: true,
            dst: "149.154.167.51".to_string(),
            domain: "worker.example".to_string(),
            skip_tls_verify: false,
            connect_timeout: Duration::from_secs(1),
            disable_tls: false,
        });
    }

    assert_eq!(pool.cf_refill_task_spawns.load(Ordering::Relaxed), 1);
}
