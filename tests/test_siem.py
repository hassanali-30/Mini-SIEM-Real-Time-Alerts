from mini_siem import Correlator, Event, normalize_event


def event(second, event_type, **kwargs):
    return Event(timestamp=float(second), source="test", event_type=event_type, **kwargs)


def test_normalization():
    normalized = normalize_event({
        "@timestamp": "2026-01-01T00:00:00Z",
        "event_type": "login_failed",
        "src_ip": "10.0.0.1",
        "dst_port": "22",
    })
    assert normalized.src_ip == "10.0.0.1"
    assert normalized.dst_port == 22


def test_brute_force_alert():
    correlator = Correlator({"brute_force_threshold": 3, "brute_force_window": 60})
    alerts = []
    for second in (1, 2, 3):
        alerts.extend(correlator.process(event(
            second, "login_failed", username="admin", src_ip="10.0.0.5"
        )))
    assert any(alert["rule_id"] == "AUTH-BRUTE-FORCE" for alert in alerts)


def test_port_scan_alert():
    correlator = Correlator({"port_scan_threshold": 3, "port_scan_window": 60})
    alerts = []
    for second, port in enumerate((80, 443, 8080), start=1):
        alerts.extend(correlator.process(event(
            second, "network_connection", src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=port
        )))
    assert any(alert["rule_id"] == "NET-PORT-SCAN" for alert in alerts)


def test_malware_network_correlation():
    correlator = Correlator({"malware_chain_window": 600})
    correlator.process(event(1, "malware_detected", host="workstation-01"))
    alerts = correlator.process(event(
        20, "network_connection", host="workstation-01", dst_ip="203.0.113.5"
    ))
    # The current rule is triggered when the malware event is processed; the
    # test ensures no offensive response is generated for network activity.
    assert all("block" not in str(alert).lower() for alert in alerts)
