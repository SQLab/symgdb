from tornado import websocket, web, ioloop, template
import time
import json
import signal
import os
import prctl

cl = []


class IndexHandler(web.RequestHandler):
    def get(self):
        self.render("index.html")


class SocketHandler(websocket.WebSocketHandler):
    def check_origin(self, origin):
        return True

    def open(self):
        if self not in cl:
            cl.append(self)
            print("Client connected")
            self.write_message('hello')

    def on_message(self, message):
        print(message)

    def on_close(self):
        if self in cl:
            cl.remove(self)
            print("Client disconnected")


class TraceHandler(web.RequestHandler):
    def get(self, id):
        id = int(id)
        data = json.dumps({"id": 1})
        self.write(data)

    def post(self):
        pass


class TraceCountHandler(web.RequestHandler):
    def get(self):
        data = json.dumps(self.analysis.get_traces_count())
        self.write(data)


settings = {"static_path": "dist", "template_path": "templates", "debug": True}

app = web.Application([(r'/', IndexHandler), (r'/ws', SocketHandler),
                       (r'/traces/(\d+)', TraceHandler),
                       (r'/traces/count', TraceCountHandler)], **settings)


def memory_changed_handler(event):
    gdb.write("event type: memory_changed")
    gdb.write("exit code: %d" % (event.address))
    gdb.write("exit code: %d" % (event.length))
    gdb.flush()


app.listen(3000)

gdb.write("start web server\n")
gdb.flush()


#gdb.events.memory_changed.connect (memory_changed_handler)
class ReadMemory(gdb.Command):
    def __init__(self):
        super(ReadMemory, self).__init__("readmemory", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = arg.split()
        address = int(args[0])
        memory_view = gdb.selected_inferior().read_memory(address, 8)
        print(bytes(memory_view))


class Triton(gdb.Command):
    def __init__(self):
        super(Triton, self).__init__("triton", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = arg.split()
        print(args[0])
        print(args[1])


ReadMemory()
Triton()
"""
if os.fork() == 0:
    prctl.set_pdeathsig(signal.SIGKILL)
    ioloop.IOLoop.instance().start()
"""
