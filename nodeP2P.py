#!/usr/bin/env python3

import time
from blockchain import *
from p2pnetwork.node import Node
import json
import base64
import argparse
import socket

PORT = 31146
HOST = "0.0.0.0"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Node Client Script")
    parser.add_argument("HOST", help="IP to listen on", default="127.0.0.1")
    parser.add_argument("PORT", help="port to listen on", default=31146)
    parser.add_argument("-t", "--thost", help="target host to connect to", dest="thost", default="127.0.0.1")
    parser.add_argument("-p", "--tport", help="target port to connect to", dest="tport", default=9001)
    parser.add_argument("-c", "--connect", dest="connect", action="store_true")


    conf = vars(parser.parse_args())
    PORT, HOST = int(conf["PORT"]), conf["HOST"]
    thost, tport = conf["thost"], int(conf["tport"])
    connect = conf["connect"]
class BasicNode(Node):
    """A Basic Class which deals with fundemental protocols that any user on the Blockchain P2P Network should be able to perform
    This includes initiating Handshakes and retrieving lists of known endpoints. This class be built upon to specialise to either node, miner or user tasks"""
    def __init__(self, host, port, known_host, known_port, TYPE, id=None, callback=None, max_connections=5):
        super(BasicNode, self).__init__(host, port, id, callback, max_connections)
        self.host = host
        self.port = port

        #stores hosts and ports of connected nodes
        self.known_nodes = {}
        #Known node which we can connect to initially
        self.known_nodes[known_host] = known_port

        #CONSTANTS
        assert TYPE in ["NODE", "MINER"], "Invalid Type for Basic Node"
        self.TYPE = TYPE
        self.protocol = {"PROTOCOL": "PSKA 0.1"}
        self.EOT_CHAR = 0x04.to_bytes(1, 'big')


    def requestBlockchain(self, connected_node, outbound=True, response=None):
        raise NotImplementedError
    def requestLedger(self, connected_node, outbound=True, response=None):
        raise NotImplementedError
    def handleTransmitBlock(self, connected_node, outbound=True, response=None):
        raise NotImplementedError
    def handleTransmitTransaction(self, connected_node, outbound=True, response=None):
        raise NotImplementedError
    
    def handleIPList(self, connected_node, outbound=True, response=None):
        if outbound:
            data = {**self.protocol, "REQUEST": "IPLIST"}
            self.send_to_node(connected_node, data)#send a request to the server for their list of known nodes
            response = self.getResponse(connected_node)#get response <<----- THIS NEEDS TO BE FIXED
            if "IPLIST" in response.keys():
                iplist = b64DecodeDictionary(response["IPLIST"])
                print("Received IP list - {0}".format(iplist))
                #self.known_nodes.update(iplist) #update our IPLIST <<---- THIS IS VULNERABLE TO UNAUTHORISED DATA MODIFICATION
                return iplist
        else: #Server side
            if "REQUEST" in response.keys() and response["REQUEST"] == "IPLIST":
                validation = {**self.protocol, "IPLIST": b64EncodeDictionary(self.known_nodes)}
                self.send_to_node(connected_node, validation) #Send our validation
    def handleHandshake(self, connected_node, outbound=True, response=None): #A command which connects to a new IP and starts a handshake
        if outbound: #Client side
            data = {**self.protocol, "VERIFY":"TYPE"} #ask node to verify that it is a node
            self.send_to_node(connected_node, data)
            response = self.getResponse(connected_node) #get reponse
            if "TYPE" in response.keys(): 
                if response["TYPE"] in  ["NODE", "MINER"]: #if it is indeed a node, store it as a known node
                    host = connected_node.host
                    port = connected_node.port
                    self.known_nodes[host] = port #update our known nodes
                    print("Known nodes - {0}".format(self.known_nodes))
        else: #Server side
            if "VERIFY" in response.keys():
                if response["VERIFY"] == "TYPE":
                    validation = {**self.protocol, "TYPE":self.TYPE}
                    self.send_to_node(connected_node, validation)
    def checkProtocol(self, connected_node, message): #Makes sure that the protocl we are communicating on is valid although this can easily be avoided
        if "PROTOCOL" in message.keys() and message["PROTOCOL"] == self.protocol["PROTOCOL"]:
            return True
        else:
            data = {**self.protocol, "ERROR":"Invalid Protocol"}
            self.send_to_node(connected_node, data)
            self.disconnect_with_node(connected_node)
            return False
    
    def getResponse(self, connected_node):
        buffer = b''
        buffer += connected_node.sock.recv(4096)
        eot_pos = buffer.find(self.EOT_CHAR)
        response = connected_node.parse_packet(buffer[:eot_pos])
        if response is not None and self.checkProtocol(connected_node, response):
            return response
        else:
            return None
    


    def node_message(self, connected_node, data):
        print("node_message from " + connected_node.id + ": " + str(data))
        if self.checkProtocol(connected_node, data):
            self.handleHandshake(connected_node, outbound=False, response=data)
            self.handleIPList(connected_node, outbound=False, response=data)
    
    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)
    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)
    

    #Copied from source code
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
                print("connect_with_node: Already connected with this node (" + node.id + ").")
                return True

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.debug_print("connecting to %s port %s" % (host, port))
            sock.connect((host, port))

            # Basic information exchange (not secure) of the id's of the nodes!
            sock.send(self.id.encode('utf-8')) # Send my id to the connected node!
            connected_node_id = sock.recv(4096).decode('utf-8') # When a node is connected, it sends it id!

            # Fix bug: Cannot connect with nodes that are already connected with us!
            for node in self.nodes_inbound:
                if node.host == host and node.id == connected_node_id:
                    print("connect_with_node: This node (" + node.id + ") is already connected with us.")
                    return True

            thread_client = self.create_new_connection(sock, connected_node_id, host, port)
            thread_client.start()

            self.nodes_outbound.append(thread_client)
            #self.outbound_node_connected(thread_client)
            return thread_client #This line has been added to make everything much easier
        except Exception as e:
            self.debug_print("TcpServer.connect_with_node: Could not connect with node. (" + str(e) + ")")
class P2PNode(BasicNode):
    """This class builds upon the BasicNode class and is specialised to perform any task that a node can perform including receiving and verifying blocks (although this is done in the Blockchain class), Transmitting blocks and transactions.
    """
    def __init__(self, host, port, known_host, known_port, blockchain=None, verify=False):
        super(P2PNode, self).__init__(host, port, known_host, known_port, "NODE")

        self.blockchain = blockchain
        if verify:
            if not verifyBlockchain(self.blockchain):
                raise ValueError("Invalid Blockchain")
    def startup(self): #run this automatically when class is initiated
        for host, port in self.known_nodes.items():
            self.getNodes(host, port)
        if self.blockchain == None:#If we do not have a valid blockchain, then request it from another node
            blockchain = self.requestBlockchain()
            if blockchain is not None:
                self.blockchain = blockchain
    def getNodes(self, host, port):
        """This visits a node, adds it to our known_nodes dict using handleHandshake,
        requests the IPList and then repeats for every node in that list"""
        thread_client = self.connect_with_node(host, port)
        self.handleHandshake(thread_client)
        iplist = self.handleIPList(thread_client)
        self.disconnect_with_node(thread_client)
        if iplist is not None:
            for host, port in iplist.items():
                if host not in self.known_nodes.keys() or self.known_nodes[host] != port:

                    getNodes(host, port)#repeat process recursively
    def verifyBlockchain(self, blockchain):#check whether our blockchain is valid
        tempblockchain = Blockchain()
        blockchain = blockchain.getBlockChain()
        for hash, block in blockchain.items():
            if not tempblockchain.addBlock(block):
                return False
        return True#Once every block is checked, we know that is indeed valid
    def requestBlockchain(self, connected_node, outbound=True, response=None):#request full blockchain from node
        if outbound:
            data = {**self.protocol, "REQUEST":"BLOCKCHAIN"}#Send request for a blockchain
            self.send_to_node(connected_node, data)
            response = self.getResponse(connected_node)#get response
            if "BLOCKCHAIN" in response.keys():
                blockchain = Blockchain()
                #Dictionary which stores block_hash:block_class_info_dictionary
                blockchain_info = b64DecodeDictionary(response["BLOCKCHAIN"])#create new temporary blockchain
                for hash, info in blockchain_info.items():
                    block = Block()
                    block.block = info
                    if not blockchain.addBlock(block):#validate our blockchain
                        return None#if not valid return None
                return blockchain
        else:#Server side (TODO:Split this into a separate function?)
            if "REQUEST" in response.keys() and response["REQUEST"] == "BLOCKCHAIN":#If the request is valid, send the blockchain information
                blockchain_info = {hash:block.getBlock()  for hash, block in self.blockchain.getBlockChain().items()}
                data = {**self.protocol, "BLOCKCHAIN": b64EncodeDictionary(blockchain_info)}
                self.send_to_node(connected_node, data)
    def transmitBlock(self, connected_node, block):#Transmits an individual block NODE AND MINER
        data = {**self.protocol, "TRANSMIT_BLOCK":"HASH "+str(block.getHash())}#Send hash of block
        self.send_to_node(connected_node, data)
        response = self.getResponse(connected_node)
        if "TRANSMIT_BLOCK" in response.keys() and response["TRANSMIT_BLOCK"] == "NONE":#If the connected node does not have that block, send the full block
            block_data = {**self.protocol, "TRANSMIT_BLOCK": b64EncodeDictionary(block.getBlock()), "TRANSMIT_TRANSACTIONS": b64EncodeDictionary(block.transactions)}
            self.send_to_node(connected_node, block_data)
    def receiveBlock(self, connected_node, response):#MINER and NODE
        if "TRANSMIT_BLOCK" in response.keys():
            hash = response["TRANSMIT_BLOCK"].lstrip("HASH ")#Parse response and extract block hash
            if hash in self.blockchain.getBlockChain().keys():#Check if we have block hash
                validation = {**self.protocol, "TRANSMIT_BLOCK": "EXISTS"}#We have the block, we do not need it
                self.send_to_node(connected_node, validation)
            else:
                validation = {**self.protocol, "TRANSMIT_BLOCK": "NONE"}#We do not have the block, send the block to us
                self.send_to_node(connected_node, validation)
                response = self.getResponse(connected_node)
                print("Response - {0}".format(response))
                block_info = b64DecodeDictionary(response["TRANSMIT_BLOCK"])
                transaction_info = b64DecodeDictionary(response["TRANSMIT_TRANSACTIONS"])
                block = Block()
                block.block = block_info
                block.transactions = transaction_info
                self.blockchain.addBlock(block)
                return block#return block
    def transmitTransaction(self, connected_node, transaction): #USER AND NODE
        data = {**self.protocol, "TRANSMIT_TRANSACTION": "HASH "+transaction.getSignature()}
        self.send_to_node(connected_node, data)
        response = self.getResponse(connected_node)
        if "TRANSMIT_TRANSACTION" in response.keys() and response["TRANSMIT_TRANSACTION"] == "NONE":
            txn_data = {**self.protocol, "TRANSMIT_TRANSACTION": b64EncodeDictionary(transaction.info)}
            self.send_to_node(connected_node, txn_data)
    def receiveTransaction(self, connected_node, response):#MINER USER AND NODE
        if "TRANSMIT_TRANSACTION" in response.keys():
            hash = response["TRANSMIT_TRANSACTION"].lstrip("HASH ")
            if hash in self.blockchain.ledger.pool:
                validation = {**self.protocol, "TRANSMIT_TRANSACTION": "EXISTS"}
                self.send_to_node(connected_node, validation)
            else:
                validation = {**self.protocol, "TRANSMIT_TRANSACTION": "NONE"}
                self.send_to_node(connected_node, validation)
                response = self.getResponse(connected
    def node_message(self, connected_node, data):
        super(P2PNode, self).node_message(connected_node, data)
        if self.checkProtocol(connected_node, data):
            self.requestBlockchain(connected_node, outbound=False, response=data)
            block = self.receiveBlock(connected_node, data)
            if block is not None:
                print(block)
                print(block.block)
def b64EncodeDictionary(data):
    return base64.b64encode(json.dumps(data).encode("ascii")).decode("ascii")
def b64DecodeDictionary(data):
    return json.loads(base64.b64decode(data.encode("ascii")).decode("ascii"))

blockchain = Blockchain()
ledger = blockchain.ledger
node = P2PNode(HOST, PORT, HOST, PORT, blockchain=blockchain) #The last two args should be a node which is always up
node.start()
if connect:
    thread_client = node.connect_with_node(thost, tport)
    node.handleHandshake(thread_client)
    mineruser = wallet.Wallet(blockchain, ledger)
    initialBlock = Block(prevHash="0"*64)
    miner = Miner(initialBlock, mineruser, ledger)
    node.transmitBlock(thread_client, initialBlock)
    node.disconnect_with_node(thread_client)
    node.stop()
