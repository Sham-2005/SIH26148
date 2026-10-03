"""Controlled JOCKY bytecode VM.

The VM never evaluates source text and never exposes arbitrary shell/Python
execution. CALL_FORENSIC is delegated to an injected, policy-aware dispatcher.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from compiler.bytecode.format import BytecodeImage, Instruction
from compiler.bytecode.opcodes import Opcode


class VMExecutionError(RuntimeError):
    pass


@dataclass
class VMResult:
    status: str
    variables: Dict[str, Any] = field(default_factory=dict)
    forensic_calls: List[Dict[str, Any]] = field(default_factory=list)
    evidence_sealed: bool = False
    steps: int = 0


class JockyVM:
    def __init__(
        self,
        dispatcher: Optional[Callable[[str, List[Any]], Any]] = None,
        max_steps: int = 10000,
    ) -> None:
        self.dispatcher = dispatcher
        self.max_steps = max_steps

    def execute(self, image: BytecodeImage) -> VMResult:
        stack: List[Any] = []
        variables: Dict[str, Any] = {}
        calls: List[Dict[str, Any]] = []
        pc = 0
        steps = 0
        sealed = False

        while pc < len(image.instructions):
            steps += 1
            if steps > self.max_steps:
                raise VMExecutionError("JOCKY VM execution step limit exceeded")

            inst: Instruction = image.instructions[pc]
            op = inst.opcode

            if op == Opcode.CONST:
                stack.append(image.constants[inst.operand])
            elif op == Opcode.LOAD:
                if inst.operand not in variables:
                    raise VMExecutionError(f"Undefined VM variable: {inst.operand}")
                stack.append(variables[inst.operand])
            elif op == Opcode.STORE:
                if not stack:
                    raise VMExecutionError("STORE requires a stack value")
                variables[inst.operand] = stack.pop()
            elif op == Opcode.CALL_FORENSIC:
                meta = dict(inst.operand or {})
                argc = int(meta.get("argc", 0))
                if len(stack) < argc:
                    raise VMExecutionError("CALL_FORENSIC stack underflow")
                args = stack[-argc:] if argc else []
                if argc:
                    del stack[-argc:]
                function = str(meta.get("function", ""))
                if function not in image.capabilities:
                    raise VMExecutionError(f"Capability not present in bytecode image: {function}")
                calls.append({"function": function, "arguments": args})
                result = self.dispatcher(function, args) if self.dispatcher else None
                stack.append(result)
            elif op == Opcode.POP:
                if stack:
                    stack.pop()
            elif op == Opcode.JUMP:
                pc = int(inst.operand)
                continue
            elif op == Opcode.JUMP_IF_FALSE:
                if not stack:
                    raise VMExecutionError("JUMP_IF_FALSE requires a condition")
                condition = stack.pop()
                if not condition:
                    pc = int(inst.operand)
                    continue
            elif op == Opcode.SEAL_EVIDENCE:
                sealed = True
            elif op == Opcode.HALT:
                break
            else:
                raise VMExecutionError(f"Unsupported opcode: {op}")

            pc += 1

        return VMResult(
            status="SUCCESS",
            variables=variables,
            forensic_calls=calls,
            evidence_sealed=sealed,
            steps=steps,
        )
