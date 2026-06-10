#!/usr/bin/env python3
"""
Patch script to add reconnaissance API endpoints to server.py
"""
import os

SERVER_FILE = "sentinel_x_ultra/sentinel_x_ultra/server.py"

# Read the server file
with open(SERVER_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Check if already patched
if "from .recon_api import register_recon_endpoints" in content:
    print("Already patched - import exists")
else:
    # Add import after Phase 5 imports
    phase5_import_end = content.find("from .agents.phase5 import (")
    if phase5_import_end != -1:
        phase5_import_end = content.find(")\n", phase5_import_end) + 2
        import_line = "\n# Reconnaissance tools integration (Phase 3 extended)\nfrom .recon_api import register_recon_endpoints\n"
        content = content[:phase5_import_end] + import_line + content[phase5_import_end:]
        print("Added import statement")
    else:
        print("Could not find Phase 5 imports - manual patch required")
        exit(1)

# Add registration call after app creation (find "# CORS middleware")
cors_marker = "# CORS middleware"
if "register_recon_endpoints(app)" not in content:
    cors_pos = content.find(cors_marker)
    if cors_pos != -1:
        # Add registration before CORS middleware
        registration = "# Register reconnaissance API endpoints\nregister_recon_endpoints(app)\n\n"
        content = content[:cors_pos] + registration + content[cors_pos:]
        print("Added registration call")
    else:
        print("Could not find CORS middleware marker - manual patch required")
        exit(1)
else:
    print("Already patched - registration exists")

# Write the patched file
with open(SERVER_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print("Patch complete!")