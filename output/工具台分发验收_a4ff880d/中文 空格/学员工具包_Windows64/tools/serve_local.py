"""Serve only this toolkit on loopback, opening the local offline CyberChef."""
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from functools import partial
import webbrowser
ROOT=Path(__file__).resolve().parent.parent
server=ThreadingHTTPServer(('127.0.0.1',0),partial(SimpleHTTPRequestHandler,directory=str(ROOT)))
url=f'http://127.0.0.1:{server.server_port}/tools/CyberChef/CyberChef_v9.28.0.html'
print(url,'\nOffline local server. Close this window or press Ctrl+C to stop.',flush=True)
webbrowser.open(url)
try:server.serve_forever()
except KeyboardInterrupt:pass
finally:server.server_close()
