from enum import IntEnum
from qiling import Qiling
from qiling.const import QL_OS
from qiling.os.os import QlOs
from qiling.core_hooks import QlCoreHooks
from qiling.exception import QlMemoryMappedError
from qiling.arch.x86_const import *
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_MODE_32, UC_MODE_64

from capstone import *
from unicorn import UcError

class parser():
    @staticmethod
    def parse_GDT(ql, seg_val: int):
        gdt_address = ql.arch.regs.read(UC_X86_REG_GDTR)[1]
        # TODO Check out of limit
        segment_descriptor = int.from_bytes(ql.mem.read(gdt_address + seg_val, 8), "little")
        base = ((segment_descriptor & 0xFF00000000000000) >> 32) + ((segment_descriptor & 0x000000FF00000000) >> 16) + ((segment_descriptor & 0x00000000FFFF0000) >> 16)
        return segment_descriptor, base

class debug_state():
    regs : dict
    last_insn_address : int
    last_insn_size :int

    def __init__(self, ql: Qiling):
        self.regs = ql.arch.regs.save()
        self.last_insn_address = ql.entry_point
        self.last_insn_size = 0

class Ret_Status(IntEnum):
    emul_start = 0,
    emul_stop = 1,
    ch_mode_32 = 2,
    ch_mode_64 = 3,
    x64_reft = 4

class QlOsSmm(QlOs):

    type = QL_OS.SMM
    stop_status : Ret_Status
    global_instruction_counter: int
    last_state: debug_state
    is_long_mode: bool = False
    next_stop_flag: bool = False
    time_to_rebuild: bool = False
    msr_table: dict

    def __init__(self, ql: Qiling):
        super(QlOsSmm, self).__init__(ql)

        self.ql = ql
        self.last_state = debug_state(ql)
        self.initHooks()
        self.msr_table = dict()
        self.msr_table[0xC0000080] = 0

        # TODO Create ql.fcall convention type

    def update_last_state(self, ql: Qiling, address: int, size: int):
        self.last_state.regs = ql.arch.regs.save()
        self.last_state.last_insn_address = address
        self.last_state.last_insn_size = size

    def move_mem_from_dosmode(self):
        ql = self.ql

        for region in ql.mem.get_mapinfo():
            # 0: begin, 1: end(size), 2: perms, 3: lable, 4: data
            if region[3] == "DOS_SMRAM":
                dosmode_mem = region
            if region[3] == "SMRAM":
                smram_mem = region

        if dosmode_mem and smram_mem:
            data = ql.mem.read(dosmode_mem[0], ql.smi_x16_size)
            ql.mem.write(smram_mem[0]+ql.smi_offset, bytes(data))
            # Trace error, remake it
            # ql.mem.unmap(dosmode_mem[0], dosmode_mem[1])
        else:
            raise QlMemoryMappedError('SMM: dosmode memory relocation error')

    def check_maps(self, map_1, map_2):
        # self.ql.log.debug("regMapCheck size1: %i, size2: %i", len(map_1), len(map_2))
        for r in map_1:
            if map_2[r] != map_1[r]:
                self.ql.log.debug("REG: %s: %x, => %x" %(r, map_1[r], map_2[r]))

    def jmpf_check(self, address, insn):
        if insn.insn_name() == "ljmp":
            segment_val = insn.operands[0].value.mem.segment
            jmp_address = insn.operands[1].value.mem.segment
            self.ql.log.info("INST jmpf|segment_register_id: %x, base_register_id: %x" %(segment_val, jmp_address))
            self.move_mem_from_dosmode()
            self.stop_status = Ret_Status.ch_mode_32
            self.next_stop_flag = True

    def print_disasm(self, address, size):
        data = self.ql.mem.read(address, size)
        self.ql.log.debug("address: %x, data: %s" %(address, data))
        instruction = next( self.ql.arch.disassembler.disasm(data, address) )
        self.ql.log.debug(f"{instruction.address:#08x}: {instruction.mnemonic} {instruction.op_str} {instruction.size}")

    def wrmsr_check(self, address, insn):
        if insn.insn_name() == "wrmsr" and not self.is_long_mode:
            msr_num = self.ql.arch.regs.ecx
            msr_val = self.ql.arch.regs.eax
            self.ql.log.debug("wrmsr_check, %x %x" %(msr_num, msr_val))
            self.msr_table[msr_num] = msr_val
            self.ql.arch.uc.msr_write(msr_num, msr_val)

    def rdmsr_check(self, address, insn):
        if insn.insn_name() == "rdmsr" and not self.is_long_mode:
            msr_num = self.ql.arch.regs.ecx
            self.ql.log.debug("rdmsr_check, %x" %())
            if not self.msr_table[msr_num]:
                self.msr_table[msr_num] = 0
            self.ql.arch.regs.eax = self.msr_table[msr_num]

    def retf_check(self, address, insn):
        if insn.insn_name() == "retf":
            ret_addres = int.from_bytes( self.ql.mem.read(self.ql.arch.regs.arch_sp, 4), "little" )
            self.ql.log.info("INST retf|ret address: %x" %(ret_addres))
            self.entry_point = ret_addres
            self.ql.arch.regs.arch_sp -= 8
            self.stop_status = Ret_Status.x64_reft
            self.ql.arch.uc.emu_stop()

    def rsm_check(self, data):
        if data == b"\x0f\xAA":
            self.ql.log.info("RSM exit")
            self.ql.arch.uc.emu_stop()
            return True
        return False




    def initHooks(self):
        self.flag=False
        def main_hook( ql: Qiling, address: int, size: int):
            
            def debug_print():
                self.ql.log.debug(f"|ARCH INFO| arch: {self.ql.uc.ctl_get_arch()}, mode: {self.ql.uc.ctl_get_mode()}, cpu_model: {self.ql.uc.ctl_get_cpu_model()}" )
                try:
                    self.print_disasm(address, size)
                    new_reg_state = self.ql.arch.regs.save()
                    self.check_maps(self.last_state.regs, new_reg_state)
                except Exception as e:
                    print(e)

            if self.next_stop_flag:
                self.next_stop_flag = False
                self.ql.log.debug("# uc rebuild start! #")
                # eip - is not the best choice
                self.entry_point = self.ql.arch.regs.eip
                self.ql.arch.uc.emu_stop()
                return

            # print("MSR 0xC0000080 %x" %ql.arch.msr.read(0xC0000080))
            if (self.msr_table[0xC0000080] & 0x100) and self.ql.arch.mode != UC_MODE_64:
                self.ql.log.debug("LONG MOOD at address: %x" %address)
                self.entry_point = self.ql.arch.regs.eip + size
                self.stop_status = Ret_Status.ch_mode_64
                self.ql.arch.uc.emu_stop()

            ql.log.debug("###########################################################################")
            # self.ql.log.info("Stack: %s" %(self.ql.mem.read(self.ql.arch.regs.arch_sp, 4)))
            debug_print()

            try:
                data = ql.mem.read(address, size)
                insn = next(self.ql.arch.disassembler.disasm(data, address))
                self.rsm_check(data)
                if insn:
                    self.jmpf_check(address, insn)
                    self.rdmsr_check(address, insn)
                    self.wrmsr_check(address, insn)

                    if self.ql.arch.mode == UC_MODE_64:
                        self.retf_check(address, insn)
            except Exception as e:
                if size > 0x100:
                    data = ql.mem.read(address, 2)
                    if self.rsm_check(data):
                        return
                self.ql.log.error(e)

        def intr_hook():
            self.ql.log.info("intr_hook")

        def address_hook(ql):
            self.ql.log.info("address_hook")

        def lgdt_hook(a, b, c, d, e):
            print("lgdt_hook")
            return

        # HOOKS area

        self.ql.hook_code(main_hook)

        def handle_in(ql: Qiling, port: int, size: int):
            self.ql.log.critical("UC_X86_INS_IN happend port: %x, size: %x" %(port, size))

        def handle_out(ql: Qiling, port: int, size: int):
            self.ql.log.critical("UC_X86_INS_OUT happend port: %x, size: %x" %(port, size))

        def handle_syscall(ql: Qiling, port: int, size: int):
            self.ql.log.critical("UC_X86_INS_SYSCALL happend port: %x, size: %x" %(port, size))

        def handle_intr(ql: Qiling, int_code):
            self.ql.log.critical("INTERRUPTION happend num: %x" %(int_code))
            self.emu_error()

        def mem_invalid(ql, address):
            self.ql.log.critical("Mem invalid happend : %x" %(address))

        # hook_insn works only with UC_X86_INS_SYSCALL - UC_X86_INS_IN - UC_X86_INS_OUT
        self.ql.hook_insn(handle_in, UC_X86_INS_IN)
        self.ql.hook_insn(handle_out, UC_X86_INS_OUT)
        self.ql.hook_insn(handle_syscall, UC_X86_INS_SYSCALL)
        self.ql.hook_intr(handle_intr)
        self.ql.hook_mem_invalid(mem_invalid)
        self.ql.hook_code(self.update_last_state)

    def print_regs(self):
        print("print_regs:")
        for reg in range(UC_X86_REG_ENDING):
            try:
                if self.ql.arch.regs.read(reg) != 0:
                    print(reg, self.ql.arch.regs.read(reg))
            except Exception as e:
                print(e)
                pass

    def rebuild_uc(self, new_mode: int):
        mem_state = self.ql.mem.save()
        # TODO realize better
        self.ql.arch.update(new_mode)
        uc = self.ql.arch.uc

        # It's enough?
        if hasattr(self.ql.arch, 'msr'):
            self.ql.arch.msr.uc = uc

        for msr_reg in  self.msr_table:
            self.ql.arch.msr.write(msr_reg, self.msr_table[msr_reg])

        # for m in uc.mem_regions():
        #     self.ql.log.debug("MEM_UC: %x %x" %(m[0], m[1]) )
        # self.ql.log.debug("MEM_vals in bcp:") 

        #add part for mmio
        for val in mem_state["ram"]:
            self.ql.log.debug("%x %x %x %s %x" %(val[0], val[1], val[2], val[3], len(val[4])) )

        self.ql.mem.map_info = []   
        self.ql.mem.restore(mem_state)
        QlCoreHooks.__init__(self.ql, uc)
        self.initHooks()

        return

    def run(self):

        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        self.ql.log.debug("|OS START EMUL| EP:%x  ExitP:%x  SramBase:%x" %(self.entry_point, self.exit_point, self.ql.smram_base))

        try:
            self.ql.log.error(f'Memory map on start:')
            for info_line in self.ql.mem.get_formatted_mapinfo():
                self.ql.log.error(info_line)

            self.stop_status = Ret_Status.emul_start

            while (self.stop_status != Ret_Status.emul_stop):
                self.ql.log.debug("Emul stopped %i" %self.stop_status)
                if self.stop_status == Ret_Status.emul_start:
                    self.stop_status = Ret_Status.emul_stop
                elif self.stop_status == Ret_Status.ch_mode_32:
                    self.ql.log.debug("Ret_Status.ch_mode_32")
                    self.rebuild_uc(32)
                    self.stop_status = Ret_Status.emul_stop
                elif self.stop_status == Ret_Status.ch_mode_64:
                    self.rebuild_uc(64)
                    self.stop_status = Ret_Status.emul_stop
                elif self.stop_status == Ret_Status.x64_reft:
                    self.stop_status = Ret_Status.emul_stop
                self.ql.log.debug("|OS START EMUL| EP:%x  ExitP:%x" %(self.entry_point, self.exit_point))
                self.ql.emu_start(self.entry_point, self.exit_point, self.ql.timeout, self.ql.count)    
            return
        except UcError as e:
            self.emu_error()
            raise