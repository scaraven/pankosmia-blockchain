#!/usr/bin/env python3
from blockchain import *
from customConnection import CustomNodeConnection
from wallet import *
import socket
from p2pnetwork.node import Node
import base64
import json
import time

import threading

class BasicNode(Node):
    """A Basic Class which deals with fundemental protocols that any user on the Blockchain P2P Network should be able to perform
    This includes initiating Handshakes and retrieving lists of known endpoints. This class be built upon to specialise to either node, miner or user tasks"""
    def __init__(self, host, port, known_host, known_port, TYPE, isknown=False, id=None, callback=None, max_connections=6):
        assert isinstance(port, int) and isinstance(known_port, int), "Port and Known Port must be of type int"
        id = port#TEMPORARY
        super(BasicNode, self).__init__(host, port, id, callback, max_connections)
        self.host = host
        self.port = port

        #stores hosts and ports of connected nodes
        self.known_nodes = {}
        #Known node which we can connect to initially
        if not isknown:
            self.known_nodes[known_host] = known_port

        #CONSTANTS
        #assert TYPE in ["NODE", "MINER"], "Invalid Type for Basic Node"
        self.TYPE = TYPE
        self.protocol = {"PROTOCOL": "PSKA 0.2"}
        self.EOT_CHAR = 0x04.to_bytes(1, 'big')


    """This visits a node, adds it to our known_nodes dict using transmitHandshake,
    requests the IPList and then repeats for every node in that list"""
    def getNodes(self, host, port, visited={}):
        #connect with a node
        thread_client = self.connect_with_node(host, port)
        #transmit handshake and iplist
        self.transmitHandshake(thread_client)
        iplist = self.transmitIPList(thread_client)
        self.disconnect_with_node(thread_client)
        #if we have not received an empty iplist
        if iplist is not None:
            for host, port in iplist.items():
                #check whether we have visited a node
                if (host,port) not in visited.keys() or visited[(host, port)] == False:
                    #we have now visited the node
                    visited[(host, port)] = True
                    self.getNodes(host, port, visited=visited)#repeat process recursively
    
    def transmitIPList(self, connected_node):
        connected_node.busy = True
        data = {**self.protocol, "REQUEST": "IPLIST"}
        self.send_to_node(connected_node, data)#send a request to the server for their list of known nodes
        response = self.getResponse(connected_node)#get response from node
        if "IPLIST" in response.keys():
            iplist = b64DecodeDictionary(response["IPLIST"])
            iplist = {k:v for k,v in iplist.items() if k != self.host or v != self.port}
            print("Received IP list - {0}".format(iplist))
            self.known_nodes.update(iplist) #update our IPLIST <<---- THIS IS VULNERABLE TO UNAUTHORISED DATA MODIFICATION
            return iplist
        connected_node.busy = False
    def receiveIPList(self, connected_node, response): #Server side
        connected_node.busy = True
        if "REQUEST" in response.keys() and response["REQUEST"] == "IPLIST":
            validation = {**self.protocol, "IPLIST": b64EncodeDictionary(self.known_nodes)}
            self.send_to_node(connected_node, validation) #Send our validation
        connected_node.busy = False
    def transmitHandshake(self, connected_node, first=True): #A command which connects to a new IP and starts a handshake
        connected_node.busy = True
        data = {**self.protocol, "VERIFY":"TYPE", "FIRST":first} #ask node to verify that it is a node
        self.send_to_node(connected_node, data)
        response = self.getResponse(connected_node) #get reponse
        if "TYPE" in response.keys(): 
            if response["TYPE"] in  ["NODE", "MINER"]: #if it is indeed a node, store it as a known node
                host, port = response.pop("HOST"), response.pop("PORT")
                if host != None and port != None:
                    self.known_nodes[host] = port #update our known nodes
        self.transmitOKMessage(connected_node)#send OK message to acknowledge communication has finished
        ok = self.receiveOKMessage(connected_node)
        connected_node.busy = False
        if ok != True:#If we do not get a OK message in return then the outboud node wants to start another protocol
            self.node_message(connected_node, ok)#run the correct protocol
    def receiveHandshake(self, connected_node, response): #Server side
        connected_node.busy = True
        verify = response.pop("VERIFY", None)
        if verify == "TYPE":#check whether the header is correct
            validation = {**self.protocol, "TYPE":self.TYPE, "HOST":self.host, "PORT":self.port}#construct response
            self.send_to_node(connected_node, validation)#send response
            time.sleep(0.1)
            ok = self.receiveOKMessage(connected_node)#receive message
            if self.known_nodes.get(connected_node.host) != connected_node.port and response.pop("FIRST") == True:#if we did not initiate the conversation
                self.transmitHandshake(connected_node, first=False)#send handshake back
            else:
                self.transmitOKMessage(connected_node)#otherwise acknowledge response and exit
        connected_node.busy = False
    def transmitOKMessage(self, connected_node):#transmitting an OK message means the end of communication
        data = {**self.protocol, "MESSAGE":"OK"}#craft data
        self.send_to_node(connected_node, data)#send data
    def receiveOKMessage(self, connected_node):#this should not be run inside node_message
        connected_node.busy = True
        response = self.getResponse(connected_node)#get response
        connected_node.busy = False
        if self.checkProtocol(connected_node, response):
            if response.pop("MESSAGE", None) == "OK":
                return True#check whether we have received a standard OK Message
            else:
                return response#otherwise our peer wants to communicate further
    def checkProtocol(self, connected_node, message): #Makes sure that the protocl we are communicating on is valid although this can easily be avoided
        if "PROTOCOL" in message.keys() and message["PROTOCOL"] == self.protocol["PROTOCOL"]:
            return True
        else:#Protocol mismatch
            data = {**self.protocol, "ERROR":"Invalid Protocol"}#craft response
            self.send_to_node(connected_node, data)#send to node and then exit
            self.disconnect_with_node(connected_node)
            return False
    
    def getResponse(self, connected_node):
        content = self.getContent(connected_node)#read content from buffer
        if content != None:
            print("Found content")#debug message
            return content
        else:#sometimes the content does not arrive straight away
            with threading.Lock():
                connected_node.listen()#if our connection did not pick up the message automatically then listen for it ourselves
            content = self.getContent(connected_node)#fetch content
            if content != None:
                return content
        return None
        #raise TimeoutError("Could not get response")#if we did not receive anything, raise an error
    def getContent(self, connected_node):
        content = connected_node.content#read content from buffer
        if content != None:#if the buffer is not empty
            print("response_message from {0}: {1} @ {2}".format(connected_node.id, content, time.time()))#output debug message
            connected_node.content = None#empty buffer
            return content
        return None#return nothing
    def transmitBlock(self, connected_node, block):#Transmits an individual block NODE AND MINER
        connected_node.busy = True
        data = {**self.protocol, "TRANSMIT_BLOCK":"HASH "+str(block.getHash())}#Send hash of block
        self.send_to_node(connected_node, data)
        response = self.getResponse(connected_node)
        if "TRANSMIT_BLOCK" in response.keys() and response["TRANSMIT_BLOCK"] == "NONE":#If the connected node does not have that block, send the full block
            block_data = {**self.protocol, "TRANSMIT_BLOCK": b64EncodeDictionary(block.getBlock()), "TRANSMIT_TRANSACTIONS": b64EncodeDictionary(block.transactions)}
            self.send_to_node(connected_node, block_data)
        connected_node.busy = False
    def receiveBlock(self, connected_node, response, blockchain_keys):#MINER and NODE
        connected_node.busy = True
        if "TRANSMIT_BLOCK" in response.keys():
            hash = response["TRANSMIT_BLOCK"].lstrip("HASH ")#Parse response and extract block hash
            if hash in blockchain_keys:#Check if we have block hash
                validation = {**self.protocol, "TRANSMIT_BLOCK": "EXISTS"}#We have the block, we do not need it
                self.send_to_node(connected_node, validation)
            else:
                validation = {**self.protocol, "TRANSMIT_BLOCK": "NONE"}#We do not have the block, send the block to us
                self.send_to_node(connected_node, validation)
                response = self.getResponse(connected_node)
                block_info = b64DecodeDictionary(response["TRANSMIT_BLOCK"])#decode all the block information
                transaction_info = b64DecodeDictionary(response["TRANSMIT_TRANSACTIONS"])
                block = Block()#create a new block
                block.block = block_info
                block.transactions = transaction_info
                if block.verifyPoW() and block.verifyHeader():#verify block information
                    return block#return block
        connected_node.busy = False
    def transmitTransaction(self, connected_node, transaction): #USER AND NODE
        connected_node.busy = True
        data = {**self.protocol, "TRANSMIT_TRANSACTION": "HASH "+str(transaction.getSignature())}#send transaction hash to node
        self.send_to_node(connected_node, data)
        response = self.getResponse(connected_node)#get response
        if "TRANSMIT_TRANSACTION" in response.keys() and response["TRANSMIT_TRANSACTION"] == "NONE":#check whether we should send full transaction data
            txn_data = {**self.protocol, "INFO": b64EncodeDictionary(transaction.info), "SIGNATURE":transaction.getSignature()}#craft response
            self.send_to_node(connected_node, txn_data)#send data
        connected_node.busy = False
    def receiveTransaction(self, connected_node, response, pool):#MINER AND NODE
        connected_node.busy = True
        if "TRANSMIT_TRANSACTION" in response.keys():#check is response is correct
            hash = response["TRANSMIT_TRANSACTION"].lstrip("HASH ")#extract hash
            if hash in pool:#check whether transaction has already been stored
                validation = {**self.protocol, "TRANSMIT_TRANSACTION": "EXISTS"}#craft response
                self.send_to_node(connected_node, validation)
            else:
                validation = {**self.protocol, "TRANSMIT_TRANSACTION": "NONE"}#ask for full transaction
                self.send_to_node(connected_node, validation)
                response = self.getResponse(connected_node)
                transaction_info = b64DecodeDictionary(response["INFO"])
                signature = response["SIGNATURE"]
                transaction = NodeTransaction(transaction_info, signature, self.blockchain.ledger)
                if transaction.verifyTransaction() and transaction.verifyHeader() and hash == transaction.hash:
                    pool.add(transaction.getSignature())#add the transaction to our pool
                    return transaction
        connected_node.busy = False

    def node_message(self, connected_node, data):
        print("node_message from " + connected_node.id + ": " + str(data) + " @ " + str(time.time()))
        if self.checkProtocol(connected_node, data):#check protocl
            self.receiveHandshake(connected_node, data)#check whether we have a handshake
            self.receiveIPList(connected_node, data)#check whether a node is request the IPList
    def outbound_node_connected(self, connected_node):#we -> node
        print("outbound_node_connected: " + connected_node.id + " @ "+ str(time.time()))
    def inbound_node_connected(self, connected_node):#we <- node
        print("inbound_node_connected: " + connected_node.id + " @ "+ str(time.time()))
    def inbound_node_disconnected(self, connected_node):#we !<- node
        print("inbound_node_disconnected: " + connected_node.id + " @ "+ str(time.time()))

    def outbound_node_disconnected(self, connected_node):#we ->! node
        print("outbound_node_disconnected: " + connected_node.id)
    def send_to_node(self, connected_node, data):#send data to node
        super(BasicNode, self).send_to_node(connected_node, data)
    def create_new_connection(self, connection, id, host, port):
        return CustomNodeConnection(self, connection, id, host, port)
    def send_to_node(self, n, data):
        time.sleep(0.05)
        super(BasicNode, self).send_to_node(n, data)
    #Modified from source code
    def connect_with_node(self, host, port, reconnect=False):
        """ Make a connection with another node that is running on host with port. When the connection is made, 
            an event is triggered outbound_node_connected. When the connection is made with the node, it exchanges
            the id's of the node. First we send our id and then we receive the id of the node we are connected to.
            When the connection is made the method outbound_node_connected is invoked. If reconnect is True, the
            node will try to reconnect to the code whenever the node connection was closed."""
        if host == self.host and port == self.port:
            print("connect_with_node: Cannot connect with yourself!!")
            return False

        # Check if node is already connected with this node!
        for node in self.nodes_outbound:
            if node.host == host and node.port == port:
                #print("connect_with_node: Already connected with this node (" + node.id + ").")
                return node

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.debug_print("connecting to %s port %s" % (host, port))
            sock.settimeout(60)
            sock.connect((host, port))
            sock.settimeout(None)

            # Basic information exchange (not secure) of the id's of the nodes!
            sock.send(self.id.encode('utf-8')) # Send my id to the connected node!
            connected_node_id = sock.recv(4096).decode('utf-8') # When a node is connected, it sends it id!

            # Fix bug: Cannot connect with nodes that are already connected with us!
            for node in self.nodes_inbound:
                if node.host == host and node.id == connected_node_id:
                    #print("connect_with_node: This node (" + node.id + ") is already connected with us.")
                    self.disconnect_with_node(node)
                    self.connect_with_node(host, port)

            thread_client = self.create_new_connection(sock, connected_node_id, host, port)
            thread_client.start()

            self.nodes_outbound.append(thread_client)
            #self.outbound_node_connected(thread_client)
            return thread_client #This line has been added to make everything much easier
        except Exception as e:
            self.debug_print("TcpServer.connect_with_node: Could not connect with node. (" + str(e) + ")")

def b64EncodeDictionary(data):
    return base64.b64encode(json.dumps(data).encode("ascii")).decode("ascii")
def b64DecodeDictionary(data):
    return json.loads(base64.b64decode(data.encode("ascii")).decode("ascii"))
