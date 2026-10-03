"""AST -> JOCKY bytecode compiler.

This compiler lowers only the safe forensic DSL currently supported by the
existing compiler. The generated CALL_FORENSIC instruction carries an
allowlisted function name; the VM delegates that request to a policy-checked
host dispatcher.
"""
from __future__ import annotations

from typing import Any, Dict, List

from compiler.ast.nodes import (
    Program, ScriptDeclaration, Statement, FunctionCall,
    VariableDeclaration, Assignment, Literal, Identifier,
    IfStatement, ForStatement, BinaryOp, Expression,
)
from .format import BytecodeImage, Instruction
from .opcodes import Opcode


class BytecodeCompiler:
    def __init__(self) -> None:
        self.constants: List[Any] = []
        self.instructions: List[Instruction] = []
        self.capabilities: List[str] = []

    def _constant(self, value: Any) -> int:
        for idx, existing in enumerate(self.constants):
            if existing == value and type(existing) is type(value):
                return idx
        self.constants.append(value)
        return len(self.constants) - 1

    def _emit(self, opcode: Opcode, operand: Any = None) -> int:
        self.instructions.append(Instruction(opcode, operand))
        return len(self.instructions) - 1

    def _patch(self, index: int, operand: int) -> None:
        self.instructions[index] = Instruction(self.instructions[index].opcode, operand)

    def compile(self, program: Program) -> BytecodeImage:
        for script in program.scripts:
            self._compile_script(script)
        self._emit(Opcode.HALT)
        return BytecodeImage(
            constants=self.constants,
            instructions=self.instructions,
            capabilities=sorted(set(self.capabilities)),
            metadata={"scripts": [s.name for s in program.scripts]},
        )

    def _compile_script(self, script: ScriptDeclaration) -> None:
        for stmt in script.body:
            self._compile_statement(stmt)

    def _compile_statement(self, stmt: Statement) -> None:
        if isinstance(stmt, (VariableDeclaration, Assignment)):
            self._compile_expression(stmt.initializer if isinstance(stmt, VariableDeclaration) else stmt.value)
            self._emit(Opcode.STORE, stmt.name)
        elif isinstance(stmt, FunctionCall):
            self._compile_call(stmt)
            self._emit(Opcode.POP)
        elif isinstance(stmt, IfStatement):
            self._compile_expression(stmt.condition)
            jump_false = self._emit(Opcode.JUMP_IF_FALSE, None)
            for child in stmt.then_body:
                self._compile_statement(child)
            if stmt.else_body is not None:
                jump_end = self._emit(Opcode.JUMP, None)
                self._patch(jump_false, len(self.instructions))
                for child in stmt.else_body:
                    self._compile_statement(child)
                self._patch(jump_end, len(self.instructions))
            else:
                self._patch(jump_false, len(self.instructions))
        elif isinstance(stmt, ForStatement):
            # The current source grammar permits loops but has no collection
            # iteration opcode yet. Keep compilation explicit rather than
            # silently inventing runtime behavior.
            raise ValueError("For-loop bytecode lowering is not implemented yet")

    def _compile_expression(self, expr: Expression) -> None:
        if isinstance(expr, Literal):
            self._emit(Opcode.CONST, self._constant(expr.value))
        elif isinstance(expr, Identifier):
            self._emit(Opcode.LOAD, expr.name)
        elif isinstance(expr, FunctionCall):
            self._compile_call(expr)
        elif isinstance(expr, BinaryOp):
            # Comparisons are intentionally represented as a host-safe
            # expression descriptor for the next VM iteration. This keeps the
            # bytecode contract explicit instead of executing arbitrary code.
            self._compile_expression(expr.left)
            self._compile_expression(expr.right)
            self._emit(Opcode.CONST, self._constant({"binary_op": expr.operator}))
        else:
            raise ValueError(f"Unsupported expression: {type(expr).__name__}")

    def _compile_call(self, call: FunctionCall) -> None:
        for arg in call.arguments:
            self._compile_expression(arg)
        self.capabilities.append(call.full_name)
        self._emit(Opcode.CALL_FORENSIC, {"function": call.full_name, "argc": len(call.arguments)})
        if call.full_name == "evidence.collect":
            self._emit(Opcode.SEAL_EVIDENCE)
