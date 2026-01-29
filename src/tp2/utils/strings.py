from tp1.utils.config import logger

class Strings:
    def __init__(self) -> None:
        pass

    def get_shellcode_strings(self, shellcode: bytes) -> str:
        current = ""
        strings = []
        for byte in shellcode:
            if 32 <= byte <= 126:
                current += chr(byte)
            else:
                if current:
                    strings.append(current)
                    current = ""
        
        if not strings:
            return "Aucun string trouvé"

        return strings
