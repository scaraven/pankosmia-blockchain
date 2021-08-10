#!/usr/bin/env python3

from basicnode import *
from collections import OrderedDict

class TransactionPool():
    """This class is responsible for storing valid transactions which can be later placed into a block, this should be able to support sorting by fee amout, timestamp time and etc..."""
    def __init__(self):
        self.pool = OrderedDict()
    def sortTxn(self, by="fee"):
        sort = OrderedDict(sorted(self.pool.items(), key=lambda x:x[1][by]))
        return sort
    def addTxn(self, transaction):
         signature = transaction.getSignature()
class MinerP2P(BasicNode):
    def __init__(self, host, port, known_host, known_port):
        super(MinerP2P, self).__init__(host, port, known_host, known_port, "MINER")
        self.pool = TransactionPool()
    def node_message(self, connected_node, data):
        super(MinerP2P, self).__init__(connected_node, data)
        if self.checkProtocol(connected_node, data):
            block = self.receiveBlock(connected_node, data, [])#we pass an empty array as we will accept all blocks
            transaction = self.receiveTransaction(connected_node, data, self.pool.pool)

        
