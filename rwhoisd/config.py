"""Server global variables should be set here."""

import socket

##### Editable Configuration Options

# the port to listen on.
port = 4321
# the interface address to bind to. "" means INADDR_ANY.
server_address = ""

# the hostname to advertise in the banner.
server_hostname = socket.getfqdn()

# setting this here sets a default session response limit.  0
# means no response limit.  This should be between min_limit and
# max_limit defined below.
default_limit = 0
# set this to the maximum value that the limit can be set to
max_limit = 256
# set this to the minimum value that the limit can be set to
# if this is zero, you are allowing clients to disable query limits.
min_limit = 0

# If this is true, some logging will be done to stdout.
verbose = False

#### END Editable Configuration Options

version = "0.1"
banner_string = "%%rwhois V-1.5 %s (python-rwhoisd %s)" % \
                (server_hostname, version)

