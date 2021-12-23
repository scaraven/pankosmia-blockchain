#!/usr/bin/env python3

from basicNode import *
from blockchain import *
from collections import OrderedDict, Counter
import argparse
from miner import *
import os
import time

known_host = '127.0.0.1'
known_port = 9001

def first(s):
    """Return first item from an Ordered Dictionary
    if the dictionary is empty return an empty list"""
    if len(s) == 0:
        return []
    else:
        return next(iter(s))

class TransactionPool():
    """This class is responsible for storing valid transactions which can be later placed into a block, 
    this should be able to support sorting by fee amout, timestamp time and etc..."""
    def __init__(self):
        #define memory pool of transactions
        self.pool = OrderedDict()
    def sortTxn(self, by="fee"):
        #sort transactions by a predefined key
        sort = OrderedDict(sorted(self.pool.items(), key=lambda x:x[1][by]))
        return sort
    def addTxn(self, transaction):
        #add transaction to pool
        signature = transaction.getSignature()
        self.pool[signature] = transaction.getInfo()
    def removeTxn(self, signature):
        #remove transaction from the mempool
        self.pool.remove(signature)
class MinerP2P(BasicNode):
    """The MinerP2P class inherits from the BasicNode class and is used only by the miner role
    The class allows a miner to mine blocks and transmit them over the network.
    If the miner is new to the network, it is able to request the last valid block from a node"""
    def __init__(self, host, port, known_host, known_port, minerwallet):
        super(MinerP2P, self).__init__(host, port, known_host, known_port, "MINER")
        #define a mempool and store the miner wallet
        self.pool = TransactionPool()
        self.minerwallet = minerwallet
    def getLastBlock(self):#Visits nodes and asks for the last block hash
        hashes = [] #stores list of block hashes received from nodes
        hash = None
        #loop through all nodes
        for host, port in self.known_nodes.items():
            try:
                #connect to the node
                thread_client = self.connect_with_node(host, port)
                thread_client.busy = True
            except AttributeError:
                breakpoint()

                thread_client = self.connect_with_node(host, port)
                thread_client.busy = True
            #craft response
            data = {**self.protocol, "GET": "LAST_BLOCK_HASH"}
            self.send_to_node(thread_client, data)
            response = self.getResponse(thread_client)
            thread_client.busy = False
            self.disconnect_with_node(thread_client)
            #if the response is not empty
            if response.get("LAST_BLOCK_HASH") != None:
                hashes.append(response["LAST_BLOCK_HASH"])
        #return most common hash
        if len(hashes) > 0:
            hash = Counter(hashes).most_common(1)[0][0]
        return hash
    def node_message(self, connected_node, data):
        super(MinerP2P, self).__init__(connected_node, data)
        if self.checkProtocol(connected_node, data):
            block = self.receiveBlock(connected_node, data, [])#we pass an empty array as we will accept all blocks
            transaction = self.receiveTransaction(connected_node, data, self.pool.pool)
            if transaction is not None:
                self.pool.addTxn(transaction)#add transaction to our pool
            #if we have received a block we need to make sure that any common transactions are removed from our pool
            #as they have already been added
            if block is not None:
                transactions = block.transactions
                for transaction_hash, transaction_info in transactions.items():#loop through transactions and remove them
                    self.removeTxn(transaction_hash)
        self.connected_node.busy = False
    def mineBlock(self):
        timelastMined = time.time()
        while True:#ideally a miner will be mining forever
            #check if we have enough transactions in our pool or enough time has been passed
            if len(self.pool.pool.keys()) >= 10 or (time.time() - timelastMined) >= 5.0 :
                timelastMined = time.time()
                #get the hash of the most recent block in the blockchain
                prevHash = self.getLastBlock()
                block = Block(prevHash=prevHash)
                for hash, transaction in list(self.pool.sortTxn().items())[:min(len(self.pool.pool), 10)]: #get 10 most profitable transactions
                    block.addTransaction(transaction)
                    self.pool.removeTxn(transaction[0])
                #mine block and transmit it to all nodes
                miner = Miner(block, self.minerwallet)
                for host, port in self.known_nodes.items():#transmit block over the network
                    connected_node = self.connect_with_node(host, port)
                    self.transmitBlock(connected_node, block)
                    self.disconnect_with_node(connected_node)
def startup():
    #define command line argument parser
    parser = argparse.ArgumentParser(description="Miner Client Script")
    #we only have one argument, the miner wallet
    parser.add_argument("path", help="Wallet Private File")
    conf = vars(parser.parse_args())
    
    walletkey_path = conf["path"]
    minerwallet = Wallet()
    if os.path.isfile(walletkey_path):
        with open(walletkey_path, "rb") as fp:
            walletkey = RSA.import_key(fp.read())
        minerwallet.setKey(walletkey)#setup miner wallet
    else:
        raise ValueError("File does not exist {0}".format(walletkey_path))
    #create a new miner on port 1337
    miner = MinerP2P('127.0.0.1', 1337, known_host, known_port, minerwallet)
    miner.start()
    miner.mineBlock()
if __name__ == "__main__":
    startup()
