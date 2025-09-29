from core.server import Server
from core.shell import Shell
from threading import Thread

server = Server()
Thread(target=server.run, args=()).start()
Shell(server).run()
