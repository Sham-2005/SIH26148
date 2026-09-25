"""
JOCKY Safe Code Generator
Converts AST / IR into canonical forensic execution plans for safe dispatch to authorized agents.
"""
import hashlib
import json
from typing import Dict, Any, List
from compiler.ast.nodes import (
    Program,
    ScriptDeclaration,
    Statement,
    FunctionCall,
    VariableDeclaration,
    Assignment,
    Literal,
    Identifier,
    IfStatement,
    ForStatement,
)
from compiler.ir.ir import IRProgram, IRScript, IRInstruction, Opcode

class IRGenerator:
    def __init__(self):
        self._temp_count = 0

    def _new_temp(self) -> str:
        self._temp_count += 1
        return f"$t{self._temp_count}"

    def generate(self, program: Program) -> IRProgram:
        ir_scripts: List[IRScript] = []
        for script in program.scripts:
            ir_scripts.append(self._generate_script(script))
        return IRProgram(scripts=ir_scripts)

    def _generate_script(self, script: ScriptDeclaration) -> IRScript:
        instructions: List[IRInstruction] = []
        env: Dict[str, Any] = {}

        for stmt in script.body:
            if isinstance(stmt, VariableDeclaration):
                val = self._resolve_expr(stmt.initializer, env)
                env[stmt.name] = val
                instructions.append(IRInstruction(Opcode.STORE, dest=stmt.name, args=[val]))

            elif isinstance(stmt, Assignment):
                val = self._resolve_expr(stmt.value, env)
                env[stmt.name] = val
                instructions.append(IRInstruction(Opcode.STORE, dest=stmt.name, args=[val]))

            elif isinstance(stmt, FunctionCall):
                resolved_args = [self._resolve_expr(a, env) for a in stmt.arguments]
                if stmt.full_name == "evidence.collect":
                    instructions.append(IRInstruction(Opcode.SEAL_EVIDENCE, args=[]))
                else:
                    instructions.append(
                        IRInstruction(
                            Opcode.CALL_FORENSIC,
                            dest=self._new_temp(),
                            args=[stmt.full_name, resolved_args],
                            metadata={"function": stmt.full_name}
                        )
                    )

        return IRScript(name=script.name, instructions=instructions)

    def _resolve_expr(self, expr, env: Dict[str, Any]) -> Any:
        if isinstance(expr, Literal):
            return expr.value
        elif isinstance(expr, Identifier):
            return env.get(expr.name, f"${expr.name}")
        elif isinstance(expr, FunctionCall):
            return f"CALL({expr.full_name})"
        return None

class SafeCodeGenerator:
    """Generates deterministic JSON execution payloads for agent execution."""
    def __init__(self):
        self.ir_gen = IRGenerator()

    def generate_plan(self, program: Program) -> Dict[str, Any]:
        ir_prog = self.ir_gen.generate(program)
        tasks = []

        for ir_script in ir_prog.scripts:
            steps = []
            for idx, inst in enumerate(ir_script.instructions):
                if inst.opcode == Opcode.CALL_FORENSIC:
                    fn_name, fn_args = inst.args
                    steps.append({
                        "step_id": idx + 1,
                        "type": "forensic_call",
                        "function": fn_name,
                        "arguments": fn_args
                    })
                elif inst.opcode == Opcode.SEAL_EVIDENCE:
                    steps.append({
                        "step_id": idx + 1,
                        "type": "seal_evidence"
                    })

            plan = {
                "script_name": ir_script.name,
                "version": "1.0.0",
                "steps": steps,
            }

            canonical_bytes = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode('utf-8')
            plan_hash = hashlib.sha256(canonical_bytes).hexdigest()
            plan["plan_hash"] = plan_hash
            tasks.append(plan)

        return {
            "target": "jocky-agent-v1",
            "scripts": tasks,
            "ir": ir_prog.to_dict()
        }
