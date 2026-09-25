"""
JOCKY Intermediate Representation (IR)
Provides an abstracted linear representation of forensic execution logic.
Designed to decouple frontend parsing from both safe JSON plan emission and future LLVM targets.
"""
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Any, Dict, Optional

class Opcode(Enum):
    STORE = auto()          # var = val
    LOAD = auto()           # read var
    CALL_FORENSIC = auto()  # execute allowlisted collector
    JUMP = auto()           # unconditional branch
    JUMP_IF = auto()        # conditional branch
    LABEL = auto()          # jump target
    SEAL_EVIDENCE = auto()  # cryptographic sealing point

@dataclass
class IRInstruction:
    opcode: Opcode
    dest: Optional[str] = None
    args: List[Any] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class IRScript:
    name: str
    instructions: List[IRInstruction] = field(default_factory=list)

@dataclass
class IRProgram:
    scripts: List[IRScript] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scripts": [
                {
                    "name": s.name,
                    "instructions": [
                        {
                            "op": inst.opcode.name,
                            "dest": inst.dest,
                            "args": inst.args,
                            "meta": inst.metadata
                        }
                        for inst in s.instructions
                    ]
                }
                for s in self.scripts
            ]
        }
