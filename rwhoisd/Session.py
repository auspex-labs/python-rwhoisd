import config

class Context:
    """This class is used to hold session specific variables."""
    def __init__(self):
        # each session gets its own query parser.
        self.queryparser = None

        # these should be set by the handler
        rfile = None
        wfile = None
        
        # set some default values.
        self.limit       = config.default_limit
        self.holdconnect = False
