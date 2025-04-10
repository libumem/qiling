#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
)

from qiling.cc import QlCommonBaseCC, make_arg_list

class QlArmBaseCC(QlCommonBaseCC):
    """Calling convention base class for ARM-based systems.
    Supports arguments passing over registers and stack.
    """

    _retaddr_on_stack = False

    @staticmethod
    def getNumSlots(argbits: int) -> int:
        return 1

    def setReturnAddress(self, addr: int) -> None:
        self.arch.regs.lr = addr

    def unwind(self, nslots: int) -> int:
        # TODO: cleanup?
        return self.arch.regs.lr

class aarch64(QlArmBaseCC):
    _retreg = UC_ARM64_REG_X0
    _argregs = make_arg_list(UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7)

class aarch32(QlArmBaseCC):
    _retreg = UC_ARM_REG_R0
    _argregs = make_arg_list(UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
