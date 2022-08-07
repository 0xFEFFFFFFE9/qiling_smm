#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Any, Mapping, MutableMapping, Union

from unicorn import Uc

class QlRegisterManager:
    """This class exposes the ql.arch.regs features that allows you to directly access
    or assign values to CPU registers of a particular architecture.
    """

    def __init__(self, uc: Uc, regs_map: Mapping[str, int], pc_reg: str, sp_reg: str):
        """Initialize the registers manager.

        Args:
            uc: initialized unicorn instance
            regs_map: registers names mapped to their corresponding unicorn definitions
            pc_reg: name of the architectural program counter register
            sp_reg: name of the architectural stack pointer register
        """

        # this funny way of initialization is used to avoid calling self setattr and
        # getattr upon init. if it did, it would go into an endless recursion
        self.register_mapping: Mapping[str, int]
        super().__setattr__('register_mapping', regs_map)

        self.uc = uc
        self.uc_pc = self.register_mapping[pc_reg]
        self.uc_sp = self.register_mapping[sp_reg]

    def __getattr__(self, name: str) -> Any:
        # print("self.uc regs getter")
        # print(self.uc)
        name = name.lower()

        if name in self.register_mapping:
            return self.uc.reg_read(self.register_mapping[name])

        else:
            return super().__getattribute__(name)


    def __setattr__(self, name: str, value: Any):
        name = name.lower()

        if name in self.register_mapping:
            self.uc.reg_write(self.register_mapping[name], value)

        else:
            super().__setattr__(name, value)


    # read register
    def read(self, register: Union[str, int]):
        """Read a register value.
        """

        if type(register) is str:
            register = self.register_mapping[register.lower()]
            # print("regs_read %s: %x" %(register, self.uc.reg_read(register)))
            # print(self.uc)
        # if register == 19:
            # print("regs_read_fromUC %s: %x" %(register, self.uc.reg_read(register)), self.uc, self, self.uc._mode)
        return self.uc.reg_read(register)


    def write(self, register: Union[str, int], value: int) -> None:
        """Write a register value.
        """

        if type(register) is str:
            register = self.register_mapping[register.lower()]
        # if register == 19:
        #     print("regs_write_fromUC %s: %x" %(register, self.uc.reg_read(register)), self.uc, self)
        # ret = 
        # if register == 19:
        #     print(ret)
        #     print("regs_write_fromUC %s: %x" %(register, self.uc.reg_read(register)), self.uc, self)
        return self.uc.reg_write(register, value)


    def save(self) -> MutableMapping[str, Any]:
        """Save CPU context.
        """

        return dict((reg, self.read(reg)) for reg in self.register_mapping)


    def restore(self, context: MutableMapping[str, Any] = {}) -> None:
        """Restore CPU context.
        """

        for reg, val in context.items():
            # print("regs_restore %s: %x" %(reg, val))
            self.write(reg, val)
            # print("regs_restored %s: %x" %(reg, self.read(reg)))
            # print("regs_fromUC %s: %x" %(reg, self.uc.reg_read(self.register_mapping[reg.lower()])))
            

                


    @property
    def arch_pc(self) -> int:
        """Get the value of the architectural program counter register.
        """

        return self.uc.reg_read(self.uc_pc)


    @arch_pc.setter
    def arch_pc(self, value: int) -> None:
        """Set the value of the architectural program counter register.
        """

        return self.uc.reg_write(self.uc_pc, value)


    @property
    def arch_sp(self) -> int:
        """Get the value of the architectural stack pointer register.
        """

        return self.uc.reg_read(self.uc_sp)


    @arch_sp.setter
    def arch_sp(self, value: int) -> None:
        """Set the value of the architectural stack pointer register.
        """

        return self.uc.reg_write(self.uc_sp, value)
