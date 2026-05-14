import os
import sys
import subprocess

from dotenv import load_dotenv

load_dotenv()

UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY")
MITM_PORT = int(os.environ.get("MITM_PORT", "8080"))
CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def main() -> None:
    if not UPSTREAM_PROXY:
        print("[!] Please configure UPSTREAM_PROXY.")
        sys.exit(1)

    os.makedirs(CERTS_DIR, exist_ok=True)

    mitm_cmd = [
        "mitmdump",
        "-s",
        "addon.py",
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        str(MITM_PORT),
        "--mode",
        f"upstream:{UPSTREAM_PROXY}",
        "--set",
        f"confdir={CERTS_DIR}",
        "--ssl-insecure",
    ]

    try:
        subprocess.run(mitm_cmd)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
