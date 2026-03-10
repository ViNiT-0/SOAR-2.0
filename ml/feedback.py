import os
import sys
import argparse
import requests
from dotenv import load_dotenv


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Update SOC alert status in Elasticsearch (analyst feedback)."
    )
    parser.add_argument(
        "--id",
        required=True,
        help="Elasticsearch document ID of the alert (from Kibana or API).",
    )
    parser.add_argument(
        "--status",
        required=True,
        choices=["true_positive", "false_positive", "dismissed"],
        help="New status for the alert.",
    )
    parser.add_argument(
        "--note",
        default="",
        help="Optional analyst note / explanation.",
    )

    args = parser.parse_args(argv)

    # Load .env from project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_dotenv(os.path.join(project_root, ".env"))

    elastic_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    alert_index = "soc-alerts"

    payload = {
        "doc": {
            "status": args.status,
        }
    }

    if args.note:
        payload["doc"]["analyst_note"] = args.note

    url = f"{elastic_url}/{alert_index}/_update/{args.id}"

    try:
        resp = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=10,
        )
        if resp.status_code == 200:
            print(f"[FEEDBACK] Updated alert {args.id} → status={args.status}")
        else:
            print(f"[FEEDBACK ERROR] HTTP {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[FEEDBACK ERROR] {e}")


if __name__ == "__main__":
    main()

