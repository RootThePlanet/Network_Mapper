"""Entry point for nmap++."""

import argparse
import json
import logging
import sys
import threading
import time

from nmap_plusplus.app import create_app
from nmap_plusplus.config import load_config


def parse_args():
    parser = argparse.ArgumentParser(description="nmap++")
    parser.add_argument("--host", default=None, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 5000)")
    parser.add_argument("--debug", action="store_true", default=None, help="Enable Flask debug mode")
    parser.add_argument("--config", metavar="FILE", default=None, help="Path to YAML/JSON config file")
    parser.add_argument("--api-key", metavar="KEY", default=None, dest="api_key",
                        help="Require this API key for all /api/* requests")
    parser.add_argument("--allowed-networks", metavar="CIDR", nargs="+", default=None,
                        dest="allowed_networks",
                        help="CIDRs that scans are allowed to target")
    parser.add_argument("--output", metavar="FILE", default=None,
                        help="Dump scan result to FILE and exit (use with --headless)")
    parser.add_argument("--headless", action="store_true", default=None,
                        help="Run scan, save result, and exit without starting the web server")
    parser.add_argument("--schedule", metavar="CRON", default=None,
                        help="Re-run scans on a schedule (supports */N minute intervals, e.g. */30)")
    return parser.parse_args()


def _parse_schedule_minutes(cron: str) -> int:
    """Parse a minimal cron expression; only supports */N minute intervals."""
    cron = cron.strip()
    if cron.startswith("*/"):
        try:
            return int(cron[2:])
        except ValueError:
            pass
    raise ValueError(f"Unsupported cron expression: {cron!r}  (only */N is supported)")


def main():
    args = parse_args()

    # Load config file, then override with CLI args
    cfg = load_config(args.config)

    # CLI args override config
    host       = args.host             or cfg["host"]
    port       = args.port             or cfg["port"]
    debug      = args.debug            if args.debug is not None else cfg["debug"]
    api_key    = args.api_key          or cfg["api_key"]
    allowed    = args.allowed_networks or cfg["allowed_networks"] or None
    output     = args.output           or cfg["output"]
    headless   = args.headless         if args.headless is not None else cfg["headless"]
    schedule   = args.schedule         or cfg["schedule"]
    webhooks   = cfg.get("webhooks", [])
    history_dir = cfg.get("history_dir", "scan_history")

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if headless:
        # Run a single scan, optionally save to file, then exit
        from nmap_plusplus.scanner import NetworkScanner
        scanner = NetworkScanner(hop_limit=cfg.get("hop_limit", 4))
        result = scanner.scan()
        if output:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, default=str)
            print(f"Scan result written to {output}")
        else:
            print(json.dumps(result, indent=2, default=str))
        sys.exit(0)

    app = create_app(
        api_key=api_key,
        allowed_networks=allowed,
        webhooks=webhooks,
        history_dir=history_dir,
    )

    if schedule:
        try:
            interval_minutes = _parse_schedule_minutes(schedule)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        interval_seconds = interval_minutes * 60

        def _run_scheduled():
            while True:
                time.sleep(interval_seconds)
                try:
                    from nmap_plusplus.scanner import NetworkScanner
                    scanner = NetworkScanner(hop_limit=cfg.get("hop_limit", 4))
                    scanner.scan()
                    logging.getLogger(__name__).info("Scheduled scan complete")
                except Exception as exc:
                    logging.getLogger(__name__).error("Scheduled scan error: %s", exc)

        t = threading.Thread(target=_run_scheduled, daemon=True)
        t.start()
        print(f"Scheduled scans every {interval_minutes} minute(s)")

    print(f"nmap++ running at http://{host}:{port}")
    print("Open the URL in your browser, then click 'Load Demo' or 'Start Scan'.")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()

