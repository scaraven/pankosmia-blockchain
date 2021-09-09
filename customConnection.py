#!/usr/bin/env python3
from p2pnetwork.node import NodeConnection
import time
import socket

class CustomNodeConnection(NodeConnection):
    def __init__(self, main_node, sock, id, host, port):
        super(CustomNodeConnection, self).__init__(main_node, sock, id, host, port)
        self.busy = False

    #overwrite source code
    def run(self):
        """The main loop of the thread to handle the connection with the node. Within the
           main loop the thread waits to receive data from the node. If data is received 
           the method node_message will be invoked of the main node to be processed."""          
        buffer = b'' # Hold the stream that comes in!

        while not self.terminate_flag.is_set():

            chunk = b''
            if self.busy == False:
                try:
                    chunk = self.sock.recv(4096) 

                except socket.timeout:
                    self.main_node.debug_print("NodeConnection: timeout")

                except Exception as e:
                    self.terminate_flag.set() # Exception occurred terminating the connection
                    self.main_node.debug_print('Unexpected error')
                    self.main_node.debug_print(e)

                # BUG: possible buffer overflow when no EOT_CHAR is found => Fix by max buffer count or so?
                if chunk != b'':
                    buffer += chunk
                    eot_pos = buffer.find(self.EOT_CHAR)

                    while eot_pos > 0:
                        packet = buffer[:eot_pos]
                        buffer = buffer[eot_pos + 1:]

                        self.main_node.message_count_recv += 1
                        self.main_node.node_message( self, self.parse_packet(packet) )

                        eot_pos = buffer.find(self.EOT_CHAR)

            time.sleep(0.01)

        # IDEA: Invoke (event) a method in main_node so the user is able to send a bye message to the node before it is closed?
        self.sock.settimeout(None)
        self.sock.close()
        self.main_node.node_disconnected( self ) # Fixed issue #19: Send to main_node when a node is disconnected. We do not know whether it is inbounc or outbound.
        self.main_node.debug_print("NodeConnection: Stopped")
