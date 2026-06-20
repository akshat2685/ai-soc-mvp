# EDYSOR Auth Module — OAuth2, RBAC/ABAC, Session Management

import os
import sys
import importlib.util

# Load the parent auth.py file dynamically to resolve name collision with auth/ directory
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
auth_py_path = os.path.join(parent_dir, "auth.py")
if os.path.exists(auth_py_path):
    spec = importlib.util.spec_from_file_location("auth_parent_module", auth_py_path)
    auth_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auth_module)
    # Expose all non-private symbols
    globals().update({k: v for k, v in auth_module.__dict__.items() if not k.startswith('_')})
