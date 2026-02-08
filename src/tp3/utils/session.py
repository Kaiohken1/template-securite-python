from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger
from bs4 import BeautifulSoup
import requests
from requests import Response

class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url: str) -> None:
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url: str = url
        self.captcha_value: str = ""
        self.flag_value: int = 1000
        self.valid_flag: str = ""
        self.session = requests.Session()

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha_url: str = "http://31.220.95.27:9002/captcha.php"
        captcha: Captcha = Captcha(captcha_url, session=self.session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.session.cookies.get('PHPSESSID')
        
    def submit_request(self) -> Response:
        """
        Sends the flag and captcha.

        Returns:
            response (Response) : The response recived for the submited request
        """
        data: dict = {
            'flag' : self.flag_value,
            'captcha' : self.captcha_value,
            'submit' : "Envoyer"
        }
        logger.info(f"Flag : {data['flag']}, Captcha : {data['captcha']}")
        response: Response = self.session.post(self.url, data=data)
        return response

    def process_response(self, response: requests.Response) -> bool :
        """
        Processes the response and parse the valid flag when captured.

        Args:
            response (Response) : The response recived for the submited request
        """
        soup: BeautifulSoup = BeautifulSoup(response.text, 'html.parser')
        
        tagSuccess = soup.find('p', class_='alert-success')

        if tagSuccess:
            full_text = tagSuccess.get_text(strip=True)
            self.valid_flag = full_text.split()[-1]
            return True
        elif self.flag_value < 2000:
            self.flag_value += 1
            return False

    def get_flag(self) -> str :
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
