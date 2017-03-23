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

app.listen(3000)

gdb.write("start web server\n")
gdb.flush()
if os.fork() == 0:
    prctl.set_pdeathsig(signal.SIGKILL)
    ioloop.IOLoop.instance().start()
