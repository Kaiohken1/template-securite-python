from unittest.mock import patch
from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw
from src.tp1.utils.capture import Capture


def test_capture_init():
    # When
    capture = Capture()
    # Then
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.pktList == None
    assert capture.protocols == {}


def test_capture_init_with_interface():
    # When
    capture = Capture("eth0")
    
    # Then
    assert capture.interface == "eth0"
    assert capture.summary == ""
    assert capture.pktList == None
    assert capture.protocols == {}


def test_capture_trafic():
    # Given
    capture = Capture()
    
    # When
    capture.capture_traffic()
    
    # Then

    assert len(capture.pktList) > 0


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    result_values = list(result.values())
    # Then
    assert result is not None
    if len(result) >= 2:
        assert result_values[0] > result_values[1]

def test_sort_network_protocols_with_data():
    capture = Capture()
    capture.protocols = {
        "ARP": 10,
        "DNS": 3,
    }

    result = capture.sort_network_protocols()
    values = list(result.values())

    assert values[0] == 10
    assert values[1] == 3


def test_get_all_protocols():
    # Given
    capture = Capture()
    capture.capture_traffic()
    # When
    result = capture.get_all_protocols()

    # Then
    assert result is not None


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"
    # When
    result = capture.get_summary()
    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()
    # When
    result = capture.gen_summary()
    # Then
    assert result == capture.summary


def test_gen_summary_with_protocols():
    # Given
    capture = Capture()
    capture.protocols = {"ARP": 5, "DNS": 2}
    # When
    result = capture.gen_summary()
    # Then
    assert "ARP" in result
    assert "5" in result
    assert "DNS" in result
    assert "2" in result
    assert result == capture.summary

def test_http_analyze_sql_injection_detected():
    # Given
    capture = Capture()
    payload = b"GET /?id=1 OR 1=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80) / Raw(load=payload)
    # When
    result = capture._HttpAnalyze([pkt])
    # Then
    assert result is True

def test_http_analyze_no_attack():
    # Given
    capture = Capture()
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80) / Raw(load=payload)
    # When
    result = capture._HttpAnalyze([pkt])
    # Then
    assert result is False

def test_http_analyze_empty_list():
    # Given
    capture = Capture()
    # When
    result = capture._HttpAnalyze([])
    # Then
    assert result is False

def test_http_analyze_no_raw_layer():
    # Given
    capture = Capture()
    pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80)
    # When
    result = capture._HttpAnalyze([pkt])
    # Then
    assert result is False

def test_dns_analyze_exfiltration_detected():
    # Given
    capture = Capture()
    long_qname = "a" * 51 + ".example.com"
    pkt = IP(src="10.0.0.1") / UDP() / DNS(qr=0, qd=DNSQR(qname=long_qname))
    # When
    result = capture._DnsAnalyze([pkt])
    # Then
    assert result is True

def test_dns_analyze_normal_query():
    # Given
    capture = Capture()
    pkt = IP(src="10.0.0.1") / UDP() / DNS(qr=0, qd=DNSQR(qname="example.com"))
    # When
    result = capture._DnsAnalyze([pkt])
    # Then
    assert result is False


def test_dns_analyze_response_ignored():
    # Given — qr=1 means DNS response, should not trigger detection
    capture = Capture()
    long_qname = "a" * 51 + ".example.com"
    pkt = IP(src="10.0.0.1") / UDP() / DNS(qr=1, qd=DNSQR(qname=long_qname))
    # When
    result = capture._DnsAnalyze([pkt])
    # Then
    assert result is False


def test_dns_analyze_empty_list():
    # Given
    capture = Capture()
    # When
    result = capture._DnsAnalyze([])
    # Then
    assert result is False


def test_arp_analyze_spoofing_detected():
    # Given
    capture = Capture()
    pkt1 = Ether() / ARP(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    pkt2 = Ether() / ARP(psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")
    # When
    result = capture._ArpAnalyze([pkt1, pkt2])
    # Then
    assert result is True


def test_arp_analyze_no_spoofing():
    # Given
    capture = Capture()
    pkt1 = Ether() / ARP(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    pkt2 = Ether() / ARP(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    # When
    result = capture._ArpAnalyze([pkt1, pkt2])
    # Then
    assert result is False


def test_arp_analyze_different_ips():
    capture = Capture()
    pkt1 = Ether() / ARP(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    pkt2 = Ether() / ARP(psrc="192.168.1.2", hwsrc="11:22:33:44:55:66")
    # When
    result = capture._ArpAnalyze([pkt1, pkt2])
    # Then
    assert result is False


def test_arp_analyze_empty_list():
    # Given
    capture = Capture()
    # When
    result = capture._ArpAnalyze([])
    # Then
    assert result is False