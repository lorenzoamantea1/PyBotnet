import json
import logging
import sys

from core.server import Node
from core.logger import getLogger
from core.errors import exception_handler

logger = getLogger("main",True)

sys.excepthook = exception_handler

def load_config(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {path}")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in configuration file: {path}")
    except Exception as e:
        logger.exception(f"Unexpected error loading config: {e}")

    sys.exit(1)

if __name__ == "__main__":
    config = load_config("data/config.json")

    try:
        node = Node(
            host                   = config.get("address", {}).get("host", "0.0.0.0"),
            port                   = config.get("address", {}).get("port", 547),
            debug                  = config.get("debug", False),
            max_clients            = config.get("clients", {}).get("max_clients", 50),
            clients_overflow_sleep = config.get("clients", {}).get("client_overflow_sleep_s", 50)
        )
        node.run()
    except Exception as e:
        logger.exception(f"Node execution failed: {e}")
        sys.exit(1)
