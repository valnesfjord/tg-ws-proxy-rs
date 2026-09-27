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
