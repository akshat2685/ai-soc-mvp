import os
import py_compile
import sys

def check_compilation(directory):
    success = True
    print(f"Auditing directory: {directory}")
    for root, dirs, files in os.walk(directory):
        # Skip virtual environments and git folders
        if any(p in root for p in [".venv", "venv", ".git", "__pycache__"]):
            continue
            
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    py_compile.compile(path, doraise=True)
                    # print(f"  [OK] {path}")
                except py_compile.PyCompileError as e:
                    print(f"  [ERROR] Syntax/Compile Error in: {path}")
                    print(f"  {e}")
                    success = False
                except Exception as e:
                    print(f"  [ERROR] Unhandled Error compiling: {path}")
                    print(f"  {e}")
                    success = False
    return success

if __name__ == "__main__":
    target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
    if not check_compilation(target_dir):
        sys.exit(1)
    else:
        print("All Python files compiled successfully!")
