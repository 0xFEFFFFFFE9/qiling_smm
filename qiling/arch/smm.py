from functools import cached_property
from collections import namedtuple
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_MODE_32, UC_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_16, KS_MODE_32, KS_MODE_64
from qiling.arch.x86_const import *
from qiling.arch.arch import QlArch
from qiling.arch.msr import QlMsrManager
from qiling.arch.register import QlRegisterManager
from qiling.arch import x86_const
from qiling.const import QL_ARCH, QL_ENDIAN

Arch_param = namedtuple("Arch_param", "bits uc_mode pc_reg sp_reg")

class QlArchIntel(QlArch):
    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EL

    @cached_property
    def msr(self) -> QlMsrManager:
        """Model-Specific Registers.
        """

        return QlMsrManager(self.uc)

class QlArchX86_SMM(QlArchIntel):
    type = QL_ARCH.X86_SMM
    bits = 16
    mode = UC_MODE_16
    pc_reg = 'ip'
    sp_reg = 'sp'

    @cached_property
    def uc(self) -> Uc:
        return  Uc(UC_ARCH_X86, self.mode)

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = dict(
            **x86_const.reg_map_8,
            **x86_const.reg_map_16,
            **x86_const.reg_map_32,
            **x86_const.reg_map_64,
            **x86_const.reg_map_cr,
            **x86_const.reg_map_st,
            **x86_const.reg_map_misc,
            **x86_const.reg_map_64_b,
            **x86_const.reg_map_64_w,
            **x86_const.reg_map_64_d,
            **x86_const.reg_map_seg_base,
            **x86_const.reg_map_xmm,
            **x86_const.reg_map_ymm,
            **x86_const.reg_map_zmm
        )

        return QlRegisterManager(self.uc, regs_map, self.pc_reg, self.sp_reg)

    @cached_property
    def disassembler(self) -> Cs:
        return Cs(CS_ARCH_X86, self.mode)

    @cached_property
    def assembler(self) -> Ks:
        return Ks(KS_ARCH_X86, self.mode)

    def restore_all_regs_with_enum(self):
        out = dict()
        for reg in range(UC_X86_REG_ENDING):
            try:
                if self.regs.read(reg):# != 0 and (reg not in (32, 33)):
                    out[reg] = self.regs.read(reg)
            except:
                pass
        return out

    def update(self, mode):
        param = {
            16: Arch_param(16, UC_MODE_16, "ip", "sp"),
            32: Arch_param(32, UC_MODE_32, "eip", "esp"),
            64: Arch_param(64, UC_MODE_64, "rip", "rsp")
        }[mode]

        restored_regs = self.restore_all_regs_with_enum()

        if "uc" in self.__dict__:
            del self.uc
        if "assembler" in self.__dict__:
            del self.assembler
        if "disassembler" in self.__dict__:
            del self.disassembler
        if "regs" in self.__dict__:
            del self.regs

        print("ARCH PARAM| bits: %i, mode: %x, pc_reg: %s, sp_reg: %s" %(param.bits, param.uc_mode, param.pc_reg, param.sp_reg))
        old_mode = self.mode 
        self.bits = param.bits
        self.mode = param.uc_mode
        self.pc_reg = param.pc_reg
        self.sp_reg = param.sp_reg

        print(restored_regs)
        for reg, val in restored_regs.items():
            if self.mode == UC_MODE_32 and (reg == 11):
                continue
            if self.mode == UC_MODE_64 and (reg in (32, 33)):
                continue
            print(reg, val)
            self.regs.write(reg, val)

        print("ARCH SELF| bits: %i, mode: %x, pc_reg: %s, sp_reg: %s" %(self.bits, self.mode, self.pc_reg, self.sp_reg))
        return