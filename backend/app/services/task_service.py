"""
Task Service
Coordinates JOCKY script compilation, plan packaging, and task dispatch.
"""
import uuid
import json
import hashlib
from typing import Optional, Dict, Any
from compiler.lexer.lexer import Lexer
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator

class TaskService:
    @staticmethod
    def compile_jocky_script(source_code: str) -> Dict[str, Any]:
        """Compiles JOCKY script source code into a safe agent execution plan."""
        stripped = source_code.strip()
        if stripped.startswith("CASE ") or stripped.startswith("COLLECT "):
            from backend.app.services.demo_service import JockyDemoParser
            parsed = JockyDemoParser.parse(source_code)
            steps = []
            for idx, col in enumerate(parsed["collections"], 1):
                steps.append({
                    "step_id": idx,
                    "type": "forensic_call",
                    "function": f"{col['category']}.collect",
                    "arguments": [col.get("where")] if col.get("where") else []
                })
            steps.append({"step_id": len(steps) + 1, "type": "seal_evidence"})
            plan = {
                "script_name": f"DemoInvestigation_{parsed['case_id']}",
                "version": "1.0.0",
                "steps": steps,
            }
            canonical_bytes = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode('utf-8')
            plan["plan_hash"] = hashlib.sha256(canonical_bytes).hexdigest()
            return {
                "target": parsed.get("target", "jocky-agent-v1"),
                "scripts": [plan],
                "declarative": True,
                "parsed": parsed
            }

        lexer = Lexer(source_code)
        tokens = lexer.tokenize()

        parser = Parser(tokens)
        program = parser.parse()

        analyzer = SemanticAnalyzer()
        analyzer.analyze(program)

        codegen = SafeCodeGenerator()
        plan_package = codegen.generate_plan(program)
        return plan_package
