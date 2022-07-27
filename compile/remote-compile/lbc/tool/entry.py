import sys
import json
import tornado.web
import tornado.ioloop
from tornado.options import define, options
from tornado.httpserver import HTTPServer
from tornado.escape import json_encode
from surfServer import CsurfServer
from multiprocessing import Lock

define("port", default=7655, help="r compile server.", type=int)


class CsurfHandler(tornado.web.RequestHandler):
    hLock = Lock()
    surf = CsurfServer(hLock, sys.argv[1])

    def post(self):
        lines = self.request.body.decode()
        response = None
        try:
            parses = json.loads(lines)
        except json.decoder.JSONDecodeError:
            response = {
                "result": 'failed',
                'status': False,
                'code': 500,
                'res': [{'log': lines}]
            }
        if response is None:
            res = []
            for parse in parses:
                res.append(CsurfHandler.surf.proc(parse))
            response = {
                "result": 'success',
                'status': True,
                'code': 200,
                'res': res
            }
        self.write(json_encode(response))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("127.0.0.1")
    app = tornado.web.Application(
        [
            (r"/lbc", CsurfHandler),
        ],
    )
    # app.listen(options.port)
    server = HTTPServer(app)
    server.bind(options.port)
    server.start(5)

    # print("http://0.0.0.0:{}/".format(options.port))
    tornado.ioloop.IOLoop.instance().start()
