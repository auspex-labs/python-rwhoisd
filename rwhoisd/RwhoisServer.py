#! /usr/bin/python

import sys, socket, SocketServer

import config, Session
import QueryParser, QueryProcessor, DirectiveProcessor, Rwhois


# server-wide variables

query_processor     = None
directive_processor = None

class RwhoisTCPServer(SocketServer.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address,
                                        RequestHandlerClass)

    def verify_request(self, request, client_address):
        # implement access control here
        return True

class RwhoisHandler(SocketServer.StreamRequestHandler):

    def readline(self):
        try:
            return self.rfile.readline().strip()[:1024]
        except KeyboardInterrupt:
            self.quit_flag = True
            return

    def handle(self):

        self.quit_flag = False

        # output a banner
        self.wfile.write(config.banner_string);
        self.wfile.write("\r\n");

        # get a session.
        session = Session.Context()
        session.rfile = self.rfile
        session.wfile = self.wfile

        # first line
        line = self.readline()

        while not self.rfile.closed:
            if not line:
                line = self.readline()
                continue

            if line.startswith("-"):
                self.handle_directive(session, line)
            else:
                self.handle_query(session, line)
                if not session.holdconnect:
                    self.quit_flag = True

            self.wfile.flush()

            # check to see if we were asked to quit
            if self.quit_flag: break

            # next line of input
            line = self.readline()

        print "done with", self.client_address

    def handle_directive(self, session, line):
        if (line.startswith("-quit")):
            self.quit_flag = True
            self.wfile.write(Rwhois.ok())
            return
        directive_processor.process_directive(session, line)

    def handle_query(self, session, line):
        query_processor.process_query(session, line)


def usage(pname):
    print """usage: %s schema_file data_file [data_file ...]""" % pname
    sys.exit(64)
    
def init(argv):
    import MemDB

    if len(argv) < 3: usage(argv[0])
    schema_file = argv[1]
    data_files  = argv[2:]
    
    db = MemDB.MemDB()

    db.init_schema(schema_file)
    for df in data_files:
        db.load_data(df)
    db.index_data()

    QueryParser.db = db

    global query_processor, directive_processor
    
    query_processor     = QueryProcessor.QueryProcessor(db)
    directive_processor = DirectiveProcessor.DirectiveProcessor(db)

def serve():
    # initialize the TCP server
    server = RwhoisTCPServer((config.server_address, config.port),
                             RwhoisHandler)

    # and handle incoming connections
    try:
        if not config.server_address:
            print "listening on port %d" % config.port
        else:
            print "listening on %s port %d" % \
                  (config.server_address, config.port)
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print "interrupted. exiting."

    print "finished serving"
    sys.exit(0)

if __name__ == "__main__":

    init(sys.argv)
    serve()

