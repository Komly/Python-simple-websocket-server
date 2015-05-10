#!/usr/bin/env python3
import socket
import re
from  hashlib import sha1
from base64 import b64encode
from struct import unpack
from select import select



class WebsocketServer(object):

    HANDSHAKE  = 'HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: {0}\r\n\r\n'

    MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    def __init__(self, addr, handler_class):
        self.handler_class = handler_class
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.listen(socket.SOMAXCONN)
        self.clients = {}

    def run(self):
        while True:
            conn, addr = self.sock.accept()
            self.clients[conn.fileno()] = self.handler_class()
            self.clients[conn.fileno()].on_connect()

            data = conn.recv(2048)
            key = re.findall(r'Sec-WebSocket-Key:\s*(\S+)\r\n', data)[0] + self.MAGIC 
            accept = b64encode(sha1(key).digest())
            conn.send(self.HANDSHAKE.format(accept))

            bytes_to_read = 2
            state = 'HEADER'
            while True:
                data = conn.recv(bytes_to_read)
                if not data:
                    self.clients[conn.fileno()].on_disconnect()
                    del self.clients[conn.fileno()]
                    break
                if state == 'HEADER':
                    header = unpack('<BB', data)
                    fin    = header[0] >> 7
                    masked = header[1] >> 7 
                    l = header[1] & 0x7F
                    if l == 126:
                        l = unpack('<H', conn.recv(2))[0]
                    elif l == 127:
                        l = unpack('<Q', conn.recv(8))[0]
                    if masked:
                        mask = unpack('<BBBB', conn.recv(4))
                    bytes_to_read = l
                    state = 'BODY'
                elif state == 'BODY':
                    if masked:
                        bytes = bytearray(data)
                        bytes = bytearray([bytes[i] ^ mask[i % 4] for i in xrange(len(bytes))])
                        data = str(bytes)
                    self.clients[conn.fileno()].on_data(data)
                    state = 'HEADER'
                    bytes_to_read = 2
            conn.close()


class ClientHandler(object):
    def on_connect(self):
        print('New client connected...')

    def on_data(self, data):
        print('Received data from client: {0}'.format(data))

    def on_disconnect(self):
        print('Client disconnected')

server = WebsocketServer(("", 1337), ClientHandler)
server.run()
