"""Run Meridian Docs: ``python server.py --port 8080``."""

from __future__ import annotations

import argparse

import uvicorn
from meridian.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Meridian Docs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    uvicorn.run(
        create_app(),
        host=args.host,
        port=args.port,
        log_level="warning",
        access_log=False,
        timeout_keep_alive=15,
    )


if __name__ == "__main__":
    main()
