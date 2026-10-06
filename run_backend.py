#!/usr/bin/env python3
"""
VISTA AI Core — Backend Server Runner
Usage:
    python run_backend.py [--port 8000] [--host 0.0.0.0]
"""

import argparse
import sys
from pathlib import Path

# Ensure root directory is on PYTHONPATH
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn

def main():
    parser = argparse.ArgumentParser(description="VISTA AI Core API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--reload", action="store_true", help="Enable live code reloading")
    args = parser.parse_args()

    print(f"[*] Starting VISTA AI Core API at http://{args.host}:{args.port}")
    print(f"[*] API Interactive Docs: http://{args.host}:{args.port}/docs")
    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )

if __name__ == "__main__":
    main()
