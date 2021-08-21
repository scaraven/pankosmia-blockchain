#!/usr/bin/env python3

from basicNode import *
from collections import OrderedDict
import argparse
from miner import *

known_host = '127.0.0.1'
known_port = '9001'

class TransactionPool():
    """This class is responsible for storing valid transactions which can be later placed into a block, this should be able to support sorting by fee amout, timestamp time and etc..."""
    def __init__(self):
        self.pool = OrderedDict()
    def sortTxn(self, by="fee"):
        sort = OrderedDict(sorted(self.pool.items(), key=lambda x:x[1][by]))
        return sort
    def addTxn(self, transaction):
        #transaction ofType P2PTransaction
        signature = transaction.getSignature()
        self.pool[signature] = transaction.getInfo()
    def removeTxn(self, signature):
        self.pool.remove(signature)
class MinerP2P(BasicNode):
    def __init__(self, host, port, known_host, known_port, minerwallet):
        super(MinerP2P, self).__init__(host, port, known_host, known_port, "MINER")
        self.pool = TransactionPool()
        self.minerwallet = minerwallet
    def node_message(self, connected_node, data):
        super(MinerP2P, self).__init__(connected_node, data)
        if self.checkProtocol(connected_node, data):
            block = self.receiveBlock(connected_node, data, [])#we pass an empty array as we will accept all blocks
            transaction = self.receiveTransaction(connected_node, data, self.pool.pool)
            if transaction is not None:
                self.pool.addTxn(transaction)#add transaction to our pool
            if block is not None:
                transactions = block.transactions
                for transaction_hash, transaction_info in transactions.items():#loop through transactions and remove them
                    self.removeTxn(transaction_hash)
    def mineBlock(self):#TODO!
        raise NotImplementedError
def startup():
    parser = argparse.ArgumentParser(description="Miner Client Script")
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
    miner = MinerP2P('127.0.0.1', 1337, known_host, known_port, minerwallet)
    miner.start()
    
if __name__ == "__main__":
    startup()
