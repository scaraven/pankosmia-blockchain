#!/usr/bin/env python3
import argparse
from basicNode import *
from blockchain import *

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
class P2PNode(BasicNode):
    """This class builds upon the BasicNode class and is specialised to perform any task that a node can perform including receiving and verifying blocks (although this is done in the Blockchain class), Transmitting blocks and transactions.
    """
    def __init__(self, host, port, known_host, known_port, isknown=False, blockchain=None, verify=False):
        super(P2PNode, self).__init__(host, port, known_host, known_port, "NODE", isknown=isknown)

        self.blockchain = blockchain
        if verify:
            if not verifyBlockchain(self.blockchain):
                raise ValueError("Invalid Blockchain")
        self.startup()
    def startup(self): #run this automatically when class is initiated
        for host, port in self.known_nodes.items():
            self.getNodes(host, port)
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
    def requestBlockchain(self, connected_node):#request full blockchain from node
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
    def respondBlockchain(self, connected_node, response):
        if "REQUEST" in response.keys() and response["REQUEST"] == "BLOCKCHAIN":#If the request is valid, send the blockchain information
            blockchain_info = {hash:block.getBlock()  for hash, block in self.blockchain.getBlockChain().items()}
            data = {**self.protocol, "BLOCKCHAIN": b64EncodeDictionary(blockchain_info)}
            self.send_to_node(connected_node, data)
    def loopList(self, function, *args):
        for host, port in self.known_nodes.items():
            thread_client = self.connect_with_node(host, port)
            function(thread_client, *args)
    def distTxn(self, txn):
        if txn is not None:
            self.loopList(self.transmitTransaction, *(txn,))
    def distBlock(self, block):
        if block is not None:
            self.blockchain.addBlock(block)
            self.loopList(self.transmitBlock, *(block,))
    def node_message(self, connected_node, data):
        super(P2PNode, self).node_message(connected_node, data)
        if self.checkProtocol(connected_node, data):
            self.respondBlockchain(connected_node, data)
            block = self.receiveBlock(connected_node, data, self.blockchain.getBlockChain().keys())
            txn = self.receiveTransaction(connected_node, data, self.blockchain.ledger.pool)
            self.distBlock(block)
def b64EncodeDictionary(data):
    return base64.b64encode(json.dumps(data).encode("ascii")).decode("ascii")
def b64DecodeDictionary(data):
    return json.loads(base64.b64decode(data.encode("ascii")).decode("ascii"))

blockchain = Blockchain()
ledger = blockchain.ledger
isknown = False
if PORT == 9001:
    isknown = True
node = P2PNode(HOST, PORT, '127.0.0.1', 9001, isknown=isknown, blockchain=blockchain) #The last two args should be a node which is always up
node.start()
if connect:
    miner = Wallet(blockchain, ledger)
    block = Block(prevHash="0"*64)
    Miner(block, miner, ledger)
    node.blockchain.addBlock(block)
    node.distBlock(block)
