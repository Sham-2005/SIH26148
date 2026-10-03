"""Platform-neutral JOCKY bytecode opcodes.

The bytecode layer is intentionally limited to forensic-plan operations. It does
not expose shell, Python, native process creation, or arbitrary code execution.
"""
from enum import IntEnum


class Opcode(IntEnum):
    CONST = 1
    LOAD = 2
    STORE = 3
    CALL_FORENSIC = 4
    POP = 5
    JUMP = 6
    JUMP_IF_FALSE = 7
    SEAL_EVIDENCE = 8
    HALT = 255
