#!/usr/bin/env python3
"""import all the necessary libraries"""
import argparse
import atexit
from basicNode import *
from blockchain import *
import os
import time


known_port = 9001
known_host = "127.0.0.1"

class P2PNode(BasicNode):
    """This class builds upon the BasicNode class 
    and is specialised to perform any task that a node can perform including receiving and verifying blocks 
    (although this is done in the Blockchain class), Transmitting blocks and transactions.
    """
    def __init__(self, host, port, known_host, known_port, isknown=False, blockchain=None, verify=False):
        #call basicNode constructor
        super(P2PNode, self).__init__(host, port, known_host, known_port, "NODE", isknown=isknown)

        #set blockchain
        self.blockchain = blockchain
        #run exit_handler() function just before the script exits
        atexit.register(exit_handler, self)
        #if we are not the lookup node run the following block
        if not isknown:
            self.startup()
            #if we do not have a blockchain
            if self.blockchain == None:
                time.sleep(1)
                thread_client = self.connect_with_node(known_host, known_port)
                #request blockchain from 
                blockchain = self.requestBlockchain(thread_client)
                self.disconnect_with_node(thread_client)
                if blockchain != None:
                    self.blockchain = blockchain
                else:
                    raise ValueError("No valid blockchain found!")
        if verify:
            if not verifyBlockchain(self.blockchain):
                raise ValueError("Invalid Blockchain")
    def startup(self): #run this automatically when class is initiated
        #Request IPlist from known node
        v1 = {}
        while v1 != self.known_nodes and len(self.known_nodes.keys()) < 20:
            diff = set(v1.items()) ^ set(self.known_nodes.items())
            diff = {k:v for k,v in diff}
            v1 = self.known_nodes.copy()
            for host, port in diff.items():
                self.getNodes(host, port)
    def verifyBlockchain(self, blockchain):#check whether our blockchain is valid
        tempblockchain = Blockchain()
        blockchain = blockchain.getBlockChain()
        for hash, block in blockchain.items():
            if not tempblockchain.addBlock(block):
                return False
        return True#Once every block is checked, we know that is indeed valid
    def requestBlockchain(self, connected_node):#request full blockchain from node
        connected_node.busy = True
        data = {**self.protocol, "REQUEST":"BLOCKCHAIN"}#Send request for a blockchain
        self.send_to_node(connected_node, data)
        response = self.getResponse(connected_node)#get response
        if "BLOCKCHAIN" in response.keys():
            blockchain = Blockchain()
            #Dictionary which stores block_hash:block_class_info_dictionary
            blockchain_info = response["BLOCKCHAIN"]#create new temporary blockchain
            if not blockchain.openBlockchain(blockchain_info):
                return None
            return blockchain
        connected_node.busy = False
    def respondBlockchain(self, connected_node, response):
        if "REQUEST" in response.keys() and response["REQUEST"] == "BLOCKCHAIN":#If the request is valid, send the blockchain information
            blockchain_info = b64EncodeDictionary({block_hash: block.saveBlock() for block_hash, block in self.blockchain.blockchain.items()})

            data = {**self.protocol, "BLOCKCHAIN": blockchain_info}
            self.send_to_node(connected_node, data)
    def loopList(self, function, *args):#this executes a functino with arguments *args for all known nodes
        for host, port in self.known_nodes.items():
            thread_client = self.connect_with_node(host, port)
            function(thread_client, *args)
            self.disconnect_with_node(thread_client)
    def distTxn(self, txn):#distribute transaction to all known nodes
        if txn is not None:
            self.loopList(self.transmitTransaction, *(txn,))
    def distBlock(self, block):#distribute block to all known nodes
        if block is not None:
            self.blockchain.addBlock(block)
            self.loopList(self.transmitBlock, *(block,))
    def transmitBalance(self, connected_node, response):
        #check that the client is asking for a balance
        if "REQUEST" in response.keys() and response["REQUEST"] == "BALANCE":
            #find user entry
            if "USER" in response.keys():
                #tuple
                user_key = b64DecodeDictionary(response["USER"])
                #extract balance and send response
                balance = self.blockchain.ledger.getBalance(user_key)
                data = {**self.protocol, "BALANCE": balance}
                time.sleep(0.5)
                self.send_to_node(connected_node, data)
    def returnLastBlock(self, connected_node, response):
        #check response
        if "GET" in response.keys() and response["GET"] == "LAST_BLOCK_HASH":
            #retreive the last block
            last_block_hash = blockchain.returnLastBlockHash()
            #send the hash of the last block
            data = {**self.protocol, "LAST_BLOCK_HASH":last_block_hash}
            self.send_to_node(connected_node, data)
    def node_message(self, connected_node, data):
        #call node_message in BasicNode first
        super(P2PNode, self).node_message(connected_node, data)
        if self.checkProtocol(connected_node, data):
            #run all node specific response functions
            self.transmitBalance(connected_node, data)
            self.respondBlockchain(connected_node, data)
            
            #if our blockchain is not empty
            if isinstance(self.blockchain, Blockchain):
                #we can also receive transactions and blocks
                self.returnLastBlock(connected_node, data)
                block = self.receiveBlock(connected_node, data, self.blockchain.getBlockChain().keys(), self.blockchain.ledger)
                txn = self.receiveTransaction(connected_node, data, self.blockchain.ledger.pool)
                self.distBlock(block)
                self.distTxn(txn)
        connected_node.busy = False
def exit_handler(node):#run when the script exits
    if isinstance(node, P2PNode) and node.blockchain != None:#if we have run a node
        hasher = hashlib.md5()
        hasher.update(bytes(node.id, encoding="ascii"))#hash the node identifier
        if not os.path.isdir("./blockchain/"):
            os.mkdir("blockchain")
        path = os.path.join("blockchain", hasher.digest().hex() + ".blkch")#construct blockchain path
        print("[*] Saving blockchain to {0}".format(path))
        node.blockchain.saveBlockchain(path)#save the blockchain at the specified path
if __name__ == "__main__":
    #Script arguments
    parser = argparse.ArgumentParser(description="Node Client Script")
    parser.add_argument("host", help="IP to listen on", default="127.0.0.1")
    parser.add_argument("port", help="port to listen on", default=9000)
    parser.add_argument("-b", help="Blockchain blk file", dest="blockpath", default=None)
    conf = vars(parser.parse_args())
    blockchain = None
    #extract arguments
    blockpath, port, host = conf["blockpath"], int(conf["port"]), conf["host"]
    #if we have passed a path to a blockchain file
    if blockpath != None and os.path.isfile(blockpath):
        blockchain = Blockchain()
        with open(blockpath, "r") as fp:
            #open the blockchain
            blockchain.openBlockchain(fp.read())

    isknown = False
    if port == 9001:#TEMPORARY
        isknown = True
        if blockchain == None:
            blockchain = Blockchain()
    node = P2PNode(host, port, known_host, known_port, isknown=isknown, blockchain=blockchain) #The last two args should be a node which is always up
    #node.debug = True
    node.start()

