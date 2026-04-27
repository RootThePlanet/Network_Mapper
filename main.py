"""Entry point for nmap++."""

import argparse
import logging
import sys

from nmap_plusplus.app import create_app


def parse_args():
    parser = argparse.ArgumentParser(description="nmap++")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    app = create_app()
    print(f"nmap++ running at http://{args.host}:{args.port}")
    print("Open the URL in your browser, then click 'Load Demo' or 'Start Scan'.")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
