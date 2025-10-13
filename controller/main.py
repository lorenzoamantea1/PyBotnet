from core.connect import Controller
from core.shell import Shell
from core.errors import exception_handler
from threading import Thread
import json, sys

sys.excepthook = exception_handler

if __name__ == "__main__":
    with open("data/nodes.json","r") as f:
        nodes_json = json.load(f)
    nodes = [tuple(lst) for lst in nodes_json]

    client = Controller(
        nodes  =  nodes,
        debug  =  False
    )
    client.setup_sockets()

    Shell(client).run()