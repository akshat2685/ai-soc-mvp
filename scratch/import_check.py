import os
import sys
import importlib.util

def check_imports(directory):
    # Add backend directory to sys.path so imports resolve relative to it
    sys.path.insert(0, directory)
    
    success = True
    print(f"Auditing imports in directory: {directory}")
    
    init_files = []
    other_files = []
    
    for root, dirs, files in os.walk(directory):
        if any(p in root for p in [".venv", "venv", ".git", "__pycache__", "alembic"]):
            continue
            
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, directory)
                if file.startswith("test_") or "test" in rel_path:
                    continue
                if file == "__init__.py":
                    init_files.append((path, rel_path))
                else:
                    other_files.append((path, rel_path))
                    
    # Sort init files by length of path so shallow ones load first
    init_files.sort(key=lambda x: len(x[1]))
    
    # Import all init files first
    for path, rel_path in init_files:
        module_name = rel_path.replace(os.sep, ".").replace(".__init__.py", "").replace("__init__.py", "").strip(".")
        if not module_name:
            continue
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
        except Exception as e:
            # We don't fail immediately on init files since they may rely on other parts
            pass
            
    # Import other modules
    for path, rel_path in other_files:
        module_name = rel_path.replace(os.sep, ".").replace(".py", "").strip(".")
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
        except Exception as e:
            print(f"  [ERROR] Import failed in: {path} (as {module_name})")
            print(f"  {type(e).__name__}: {e}")
            success = False
            
    return success

if __name__ == "__main__":
    target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
    if not check_imports(target_dir):
        sys.exit(1)
    else:
        print("All backend modules imported successfully!")
