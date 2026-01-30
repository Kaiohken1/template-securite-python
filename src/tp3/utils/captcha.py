import requests
from src.tp3.utils.config import logger
from PIL import Image
from pytesseract import image_to_string

class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = self.get_value()

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        response = requests.get(self.url)

        if response.status_code == 200:
            with open("captcha.png", "wb") as f:
                f.write(response.content)
                logger.info(f"Captcha téléchargé avec succès.")
        else:
            logger.info(f"Erreur : {response.status_code}")


    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        img = Image.open('captcha.png')
        text = image_to_string(img)
        if len(text) != 0:
            logger.info("Erreur lors de la récupération de la valeur du captcha")
            return ""
        return text
