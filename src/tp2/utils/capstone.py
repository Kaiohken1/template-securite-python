from tp1.utils.config import logger
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

class Capstone:
    def __init__(self):
        pass

    def get_capstone_analysis(self, shellcode) -> str:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        result = ""
        for i in md.disasm(shellcode, 0x1000):
            result += (f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        return result