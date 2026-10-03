"""Deterministic JOCKY bytecode image format."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
import hashlib
import json

from .opcodes import Opcode


@dataclass(frozen=True)
class Instruction:
    opcode: Opcode
    operand: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {"op": self.opcode.name, "arg": self.operand}


@dataclass
class BytecodeImage:
    version: str = "1.0.0"
    constants: List[Any] = field(default_factory=list)
    instructions: List[Instruction] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "constants": self.constants,
            "instructions": [i.to_dict() for i in self.instructions],
            "capabilities": sorted(set(self.capabilities)),
            "metadata": self.metadata,
        }

    @property
    def image_hash(self) -> str:
        raw = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        payload = self.canonical_payload()
        payload["image_hash"] = self.image_hash
        return payload
