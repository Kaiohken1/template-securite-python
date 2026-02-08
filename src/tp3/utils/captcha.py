import requests
from requests import Session, Response
from src.tp3.utils.config import logger
from PIL import Image
from pytesseract import image_to_string

class Captcha:
    def __init__(self, url: str, session: Session):
        self.url: str = url
        self.image: Image = ""
        self.value: str = ""
        self.session: Session = session

    def solve(self) -> None:
        """
        Fonction permettant la résolution du captcha.
        """
        img: Image = Image.open('captcha.png')
        text: str = image_to_string(img)
        if len(text) <= 0:
            logger.info("Erreur lors de la récupération de la valeur du captcha")
            return ""
        self.value = text

    def capture(self) -> None:
        """
        Fonction permettant la capture du captcha.
        """
        response: Response = self.session.get(self.url)
        if response.status_code == 200:
            with open("captcha.png", "wb") as f:
                f.write(response.content)
            self.image = 'captcha.png'
        else:
            logger.info(f"Erreur : {response.status_code}")


    def get_value(self) -> str:
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
