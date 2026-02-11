from unittest.mock import patch
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
    # This is a minimal test since the method doesn't do much yet
    assert len(capture.pktList) > 0


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    result_values = list(result.values())
    # Then
    assert result is not None
    if (len(result) >= 2):
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
