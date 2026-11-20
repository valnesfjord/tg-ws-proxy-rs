use super::*;

#[test]
fn faketls_pending_uses_an_offset_and_releases_its_record() {
    let mut pending = PendingData::from_record(vec![10, 11, 12, 13, 14], 2);
    let original_ptr = pending.data.as_ptr();
    let mut first = [0u8; 2];

    assert_eq!(pending.read(&mut first), Some(2));
    assert_eq!(first, [12, 13]);
    assert_eq!(pending.data.as_ptr(), original_ptr);

    let mut last = [0u8; 2];
    assert_eq!(pending.read(&mut last), Some(1));
    assert_eq!(last[0], 14);
    assert!(pending.data.is_empty());
    assert_eq!(pending.data.capacity(), 0);
    assert_eq!(pending.read(&mut last), None);
}

#[tokio::test]
async fn client_activity_restarts_the_idle_clock() {
    let timeout = Duration::from_secs(30);
    let activity = ClientActivity(Arc::new(Mutex::new(Instant::now() - timeout)));
    let mut idle = std::pin::pin!(activity.wait_for_idle(timeout));
    assert!(futures_util::poll!(idle.as_mut()).is_ready());

    activity.record();

    let mut idle = std::pin::pin!(activity.wait_for_idle(timeout));
    assert!(futures_util::poll!(idle.as_mut()).is_pending());
}

#[tokio::test]
async fn incomplete_faketls_records_update_activity_on_socket_progress() {
    use futures_util::poll;

    let old = Instant::now() - Duration::from_secs(30);
    let activity = ClientActivity(Arc::new(Mutex::new(old)));
    let (stream, mut peer) = tokio::io::duplex(8);
    let mut stream = TrackedIo {
        inner: stream,
        activity: Some(activity.clone()),
    };
    let mut buf = [0; 32];
    peer.write_all(&[0x17, 3, 3, 0, 32, 42]).await.unwrap();
    {
        let mut read = std::pin::pin!(read_tls_appdata(&mut stream, &mut buf));
        assert!(poll!(read.as_mut()).is_pending());
        assert!(*activity.0.lock().unwrap() > old);
    }

    *activity.0.lock().unwrap() = old;
    let mut write = std::pin::pin!(write_tls_appdata(&mut stream, &buf));
    assert!(poll!(write.as_mut()).is_pending());
    assert!(*activity.0.lock().unwrap() > old);
}
