#!/usr/bin/env python3

from basicnode import *
from collections import Counter
from wallet import *

class UserP2P(BasicNode):
    def __init__(self, host, port, known_host, known_port, userwallet):
        super(UserP2P, self).__init__(host, port, known_host, known_port, "USER")
        self.user = userwallet
    def createTransaction(self, receiver, amount, fee):
        transaction = P2PTransaction(self.user.getPublic(), receiver, amount, fee, self.user.signTransaction)
        for host, port in self.known_nodes():
            thread_client = self.connect_with_node(host, port)
            self.transmitTransaction(thread_client, transaction)
    def getBalance(self):
        cnt = Counter()
        data = {**self.protocol, "REQUEST":"BALANCE", "USER":b64EncodeDictionary(self.user.getPublic())}
        for host, port in self.known_nodes():
            response = self.getResponse(connected_node)
            balance = response["BALANCE"]
            if balance is not None:
                cnt[balance] += 1
        return cnt.most_common()[0][0]#return most common balance
