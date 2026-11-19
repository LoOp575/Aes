from cnfe.database import init_db, list_scans, save_scan


def test_persist_and_list(tmp_path):
    db_path = str(tmp_path / "test.sqlite3")
    init_db(db_path)
    item = {
        "id": "scan-1",
        "created_at": "2026-11-19T00:00:00+00:00",
        "target": "example.com",
        "resolved_ip": "203.0.113.10",
        "port": 443,
        "status": "completed",
    }
    save_scan(db_path, item)
    assert list_scans(db_path, 10)[0]["id"] == "scan-1"
