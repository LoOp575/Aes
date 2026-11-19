from cnfe.config import Settings, target_is_authorized


def make_settings():
    return Settings(
        authorized_targets=("example.com", "192.168.10.0/24"),
        allowed_ports=(443, 8443),
        database_path=":memory:",
        connect_timeout=2,
        tls_timeout=2,
    )


def test_exact_hostname_allowlist():
    assert target_is_authorized("example.com", make_settings())
    assert not target_is_authorized("sub.example.com", make_settings())


def test_cidr_allowlist():
    assert target_is_authorized("192.168.10.42", make_settings())
    assert not target_is_authorized("192.168.11.42", make_settings())


def test_trailing_dot_hostname():
    assert target_is_authorized("example.com.", make_settings())
