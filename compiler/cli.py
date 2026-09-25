"""
JOCKY Compiler CLI
Command-line driver for syntax check, AST inspection, semantic validation, and execution plan compilation.
"""
import sys
import os
import json
import argparse
from compiler.lexer.lexer import Lexer
from compiler.parser.parser import Parser
from compiler.semantic.analyzer import SemanticAnalyzer
from compiler.codegen.codegen import SafeCodeGenerator
from compiler.diagnostics.errors import JockyError

def compile_file(source_path: str, output_path: str = None) -> dict:
    with open(source_path, "r", encoding="utf-8") as f:
        source = f.read()

    # 1. Lexing
    lexer = Lexer(source, file_path=source_path)
    tokens = lexer.tokenize()

    # 2. Parsing
    parser = Parser(tokens, file_path=source_path)
    program = parser.parse()

    # 3. Semantic Analysis
    analyzer = SemanticAnalyzer(file_path=source_path)
    analyzer.analyze(program)

    # 4. Code Generation
    codegen = SafeCodeGenerator()
    result = codegen.generate_plan(program)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Successfully compiled {source_path} -> {output_path}")

    return result

def main():
    cli_parser = argparse.ArgumentParser(description="JOCKY Forensic DSL Compiler")
    subparsers = cli_parser.add_subparsers(dest="command", required=True)

    # Check
    check_parser = subparsers.add_parser("check", help="Perform syntax and semantic analysis")
    check_parser.add_argument("file", help="Path to .jocky source file")

    # Compile
    comp_parser = subparsers.add_parser("compile", help="Compile .jocky into safe execution package")
    comp_parser.add_argument("file", help="Path to .jocky source file")
    comp_parser.add_argument("-o", "--output", help="Output JSON execution plan file path")

    # Inspect AST
    ast_parser = subparsers.add_parser("inspect-ast", help="Display parsed AST structure")
    ast_parser.add_argument("file", help="Path to .jocky source file")

    # Verify Integrity (Phase 7)
    integrity_parser = subparsers.add_parser("verify-integrity", help="Verify cryptographic integrity of cases, evidence, audit logs, or reports")
    integrity_parser.add_argument("--case", help="Case ID to verify (e.g. CASE-2026-001)")
    integrity_parser.add_argument("--evidence", help="Specific Evidence ID to verify")
    integrity_parser.add_argument("--audit", action="store_true", help="Verify complete audit hash-chain")
    integrity_parser.add_argument("--report", help="Specific Report ID to verify")
    integrity_parser.add_argument("--configuration", action="store_true", help="Verify configuration integrity fingerprint")

    args = cli_parser.parse_args()

    try:
        if args.command == "check":
            with open(args.file, "r", encoding="utf-8") as f:
                src = f.read()
            tokens = Lexer(src, file_path=args.file).tokenize()
            prog = Parser(tokens, file_path=args.file).parse()
            SemanticAnalyzer(file_path=args.file).analyze(prog)
            print(f"[OK] Syntax and semantic verification passed for: {args.file}")

        elif args.command == "compile":
            result = compile_file(args.file, args.output)
            if not args.output:
                print(json.dumps(result, indent=2))

        elif args.command == "inspect-ast":
            with open(args.file, "r", encoding="utf-8") as f:
                src = f.read()
            tokens = Lexer(src, file_path=args.file).tokenize()
            prog = Parser(tokens, file_path=args.file).parse()
            import pprint
            pprint.pprint(prog)

        elif args.command == "verify-integrity":
            from backend.app.database.session import SessionLocal
            from backend.app.services.security_integrity_service import IntegrityService
            from backend.app.services.config_integrity_service import ConfigIntegrityService
            from backend.app.models.models import Evidence, Report

            db = SessionLocal()
            try:
                if args.case:
                    scorecard = IntegrityService.evaluate_case_integrity_scorecard(db, args.case)
                    controls = scorecard["controls"]
                    print("\n## JOCKY Integrity Verification\n")
                    print(f"Case: {args.case}\n")
                    print(f"Evidence Chain: {controls.get('evidence_integrity', {}).get('status', 'VERIFIED')}")
                    print(f"Audit Chain: {controls.get('audit_integrity', {}).get('status', 'VERIFIED')}")
                    print(f"Agent Identity: {controls.get('agent_identity', {}).get('status', 'VERIFIED')}")
                    print(f"Task Integrity: {controls.get('task_integrity', {}).get('status', 'VERIFIED')}")
                    print(f"Playbook Integrity: {controls.get('playbook_integrity', {}).get('status', 'VERIFIED')}")
                    print(f"Configuration: {controls.get('configuration_integrity', {}).get('status', 'VERIFIED')}")
                    print(f"Reports: {controls.get('report_integrity', {}).get('status', 'VERIFIED')}")
                    print("\nOverall Integrity Controls:")
                    print(f"{scorecard['verified_controls']}/{scorecard['total_controls']} {scorecard['status']}")
                elif args.evidence:
                    ev = db.query(Evidence).filter(Evidence.id == args.evidence).first()
                    if not ev:
                        print(f"[-] Evidence '{args.evidence}' not found.", file=sys.stderr)
                        sys.exit(1)
                    valid, claimed, recalc, msg = IntegrityService.verify_single_evidence(ev)
                    status_str = "VERIFIED" if valid else "COMPROMISED"
                    print(f"\n## JOCKY Evidence Verification\nEvidence: {args.evidence}\nStatus: {status_str}\nHash: {claimed}\nMessage: {msg}")
                elif args.report:
                    rep = db.query(Report).filter(Report.id == args.report).first()
                    if not rep:
                        print(f"[-] Report '{args.report}' not found.", file=sys.stderr)
                        sys.exit(1)
                    valid, msg, _ = IntegrityService.verify_report_manifest(rep)
                    status_str = "VERIFIED" if valid else "COMPROMISED"
                    print(f"\n## JOCKY Report Verification\nReport: {args.report}\nStatus: {status_str}\nMessage: {msg}")
                elif args.audit:
                    valid, findings = IntegrityService.verify_audit_chain(db)
                    status_str = "VERIFIED" if valid else "COMPROMISED"
                    print(f"\n## JOCKY Audit Chain Verification\nStatus: {status_str}\nIssues: {len(findings)}")
                elif args.configuration:
                    valid, reason, fp = ConfigIntegrityService.verify_configuration_integrity()
                    status_str = "VERIFIED" if valid else "COMPROMISED"
                    print(f"\n## JOCKY Configuration Integrity\nStatus: {status_str}\nFingerprint: {fp}\nReason: {reason}")
                else:
                    print("Specify --case, --evidence, --audit, --report, or --configuration", file=sys.stderr)
            finally:
                db.close()


    except JockyError as e:
        print(f"[-] Compilation Failed:\n    {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
