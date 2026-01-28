from src.tp2.utils.strings import Strings
from src.tp2.utils.pylibemu import Pylibemu
from src.tp2.utils.capstone import Capstone

def main():
    shellcode = "add shellcode here"
    strings = Strings()
    pylibemu = Pylibemu()
    capstone = Capstone()
    strings.get_shellcode_strings(shellcode)
    pylibemu.get_libemu_analysis(shellcode)
    capstone.get_capstone_analysis(shellcode)
