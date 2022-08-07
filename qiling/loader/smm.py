from qiling import Qiling
from qiling.loader.loader import QlLoader
from qiling.arch.x86_const import *
from qiling.arch.x86_const import GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE

class QlLoaderSMM(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        profile = ql.profile
        ql.smram_base = profile.getint("SMM", "smram_base")
        ql.smram_size = profile.getint("SMM", "smram_size")
        ql.smi_offset = profile.getint("CPU", "SMI_OFFSET")
        ql.smi_base = ql.smram_base + ql.smi_offset
        
        self.ql = ql
        self.load_address = 0


    def dosmode_initialization(self):
        self.ql.log.debug("INIT DOS MODE")
        address = 0
        smi_offset = (self.ql.smi_base - self.ql.smram_base)
        size = self.ql.smram_size - smi_offset
        size_with_alignment = ((size >> 12) + 1) << 12;
        self.ql.smi_x16_size = size
        self.ql.mem.map(address, size_with_alignment, info = "DOS_SMRAM")

        path = self.ql.path
        with open(path, "rb") as f:
            content = f.read()
            self.ql.mem.write(address, content[smi_offset:])

        return

    def memory_initialization(self):
        try:
            self.ql.mem.map(self.ql.smram_base, self.ql.smram_size, info = "SMRAM")
            path = self.ql.path
            with open(path, "rb") as f:
                content = f.read()
                self.ql.mem.write(self.ql.smram_base, content)
        except:
            raise
        return

    def run(self, mode: int=16):
        if mode not in (16, 32, 64):
            # TODO choose right exception
            return
        self.memory_initialization()
        self.dosmode_initialization()
        self.ql.os.entry_point = 0x8000
        return
