"""
Development Environment Runner for SIH26148 JOCKY Framework
Launches FastAPI backend, simulated agent, or tests.
"""
import sys
import subprocess
import argparse

def run_backend():
    print("[*] Launching FastAPI Backend on http://localhost:8000 ...")
    subprocess.run([sys.executable, "-m", "uvicorn", "backend.app.main:app", "--reload", "--port", "8000"])

def run_tests():
    print("[*] Executing test suite across Compiler, Agent, and Backend ...")
    subprocess.run([sys.executable, "-m", "pytest", "compiler/tests", "agent/tests", "backend/tests", "-v"])

def compile_script(script_path):
    print(f"[*] Compiling JOCKY script: {script_path} ...")
    subprocess.run([sys.executable, "-m", "compiler.cli", "compile", script_path])

def main():
    parser = argparse.ArgumentParser(description="JOCKY Dev Helper")
    parser.add_argument("action", choices=["backend", "test", "compile"], help="Action to run")
    parser.add_argument("--script", help="Path to .jocky script (required for action 'compile')")
    args = parser.parse_args()

    if args.action == "backend":
        run_backend()
    elif args.action == "test":
        run_tests()
    elif args.action == "compile":
        if not args.script:
            print("[-] Please provide --script <path_to_jocky_file>")
            sys.exit(1)
        compile_script(args.script)

if __name__ == "__main__":
    main()
