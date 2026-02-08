from src.tp3.utils.config import logger
from src.tp3.utils.session import Session
from src.tp3.utils.captcha import Captcha

def main():
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {"1": f"http://{ip}/captcha1/"}

    for i in challenges:
        url = challenges[i]
        session = Session(url)
        session.prepare_request()
        response = session.submit_request()

        while not session.process_response(response) and session.flag_value < 2000:
            session.prepare_request()
            response = session.submit_request()

        if session.flag_value > 2000:
            logger.info("Could not solve {url} after 2000 attemps")
            return
    
        logger.info("Smell good !")
        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()
