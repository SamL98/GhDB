import sys

from multiprocessing.connection import Client

addr = int(sys.argv[1], 16)

address = ('localhost', 13377)
conn = Client(address)
conn.send_bytes(('goto 0x%x' % addr).encode('utf-8'))
conn.send_bytes('stop'.encode('utf-8'))
conn.close()
