"""Store one sanitized, user-owned message from standard input without echoing its contents.

    python -m scripts.add_labeled_message --label safe --channel email < message.txt
"""
from __future__ import annotations

import argparse
import sys

from app.ml.user_labels import append_labeled_message


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", choices=("safe", "scam"), required=True)
    parser.add_argument("--channel", choices=("email", "sms"), default="email")
    args = parser.parse_args()
    try:
        result = append_labeled_message(sys.stdin.read(), args.label, args.channel)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Sanitized message " + result["status"] + "; message content was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
