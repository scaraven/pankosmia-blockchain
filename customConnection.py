#!/usr/bin/env python3
from p2pnetwork.node import NodeConnection
import time
import socket
import threading

class CustomNodeConnection(NodeConnection):
    def __init__(self, main_node, sock, id, host, port):
        super(CustomNodeConnection, self).__init__(main_node, sock, id, host, port)
        self.busy = False
        self.content = None#
    #overwrite source code
    def run(self):
        """The main loop of the thread to handle the connection with the node. Within the
           main loop the thread waits to receive data from the node. If data is received 
           the method node_message will be invoked of the main node to be processed."""          
        self.buffer = b''
        while not self.terminate_flag.is_set():
            self.listen()
            time.sleep(1)

        # IDEA: Invoke (event) a method in main_node so the user is able to send a bye message to the node before it is closed?
        self.sock.settimeout(None)
        self.sock.close()
        self.main_node.node_disconnected( self ) # Fixed issue #19: Send to main_node when a node is disconnected. We do not know whether it is inbounc or outbound.
        self.main_node.debug_print("NodeConnection: Stopped")
    def listen(self):
        chunk = b''
        try:
            self.terminate_flag.wait(0.1)
            #print("Inside listen(), listening for chunk - {0}".format(time.time()))
            if not self.busy:
                chunk = self.sock.recv(4096)
            #print("Received chunk from listen() - {0}".format(time.time()))

        except socket.timeout:
            self.main_node.debug_print("NodeConnection: timeout")

        except Exception as e:
            self.terminate_flag.set() # Exception occurred terminating the connection
            self.main_node.debug_print('Unexpected error')
            self.main_node.debug_print(e)

        # BUG: possible buffer overflow when no EOT_CHAR is found => Fix by max buffer count or so?
        if chunk != b'':
            self.buffer += chunk
            eot_pos = self.buffer.find(self.EOT_CHAR)

            if eot_pos > 0:
                packet = self.buffer[:eot_pos]
                self.buffer = self.buffer[eot_pos + 1:]

                self.main_node.message_count_recv += 1
                self.main_node.node_message( self, self.parse_packet(packet) )
                eot_pos = self.buffer.find(self.EOT_CHAR)

