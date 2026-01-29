import pylibemu
from tp1.utils.config import logger

class Pylibemu:
    def __init__(self):
        pass
    
    def get_libemu_analysis(self, shellcode) -> str:
        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(shellcode)
        emulator.prepare(shellcode, offset)
        emulator.test()
        return emulator.emu_profile_output.decode()