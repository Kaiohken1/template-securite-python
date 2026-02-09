from src.tp3.utils.captcha import Captcha
from PIL import Image
from requests import Session



def test_captcha_init():
    # Given
    url = "http://example.com/captcha"
    session = Session()

    # When
    captcha = Captcha(url, session)

    # Then
    assert captcha.url == url
    assert captcha.image == ""
    assert captcha.value == ""


def test_solve():
    # Given
    session = Session()

    captcha = Captcha("http://example.com/captcha", session)

    captcha.image = Image.open('captcha_test.png')

    # When
    captcha.solve()

    # Then
    assert captcha.value == "758841"


def test_capture():
    # Given
    session = Session()
    captcha = Captcha("http://31.220.95.27:9002/captcha.php", session)

    # When
    captcha.capture()

    # Then
    assert len(captcha.image) > 0
    assert len(captcha.session) > 0


def test_get_value():
    # Given
    session = Session()
    captcha = Captcha("http://example.com/captcha", session)
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
