#!/usr/bin/env python3

from basicNode import *
from collections import Counter
from wallet import *
import argparse
import os
import time

known_host = '127.0.0.1'
known_port = 9001

#TODO: User should send transactions to more than one node

class UserP2P(BasicNode):
    def __init__(self, host, port, known_host, known_port, userwallet):
        super(UserP2P, self).__init__(host, port, known_host, known_port, "USER")
        self.user = userwallet
        self.fetchingBalance = False
        self.cnt = Counter()
    def createTransaction(self, receiver, amount, fee):#create a transaction and trasmit it
        transaction = UserTransaction(self.user.getPublic(), receiver, amount, fee, self.user.signTransaction)
        for host, port in self.known_nodes.items():
            thread_client = self.connect_with_node(host, port)
            if thread_client is not None:
                self.transmitTransaction(thread_client, transaction)
    def getBalance(self):#gets balance from remote nodes
        cnt = Counter()
        data = {**self.protocol, "REQUEST":"BALANCE", "USER":b64EncodeDictionary(self.user.getPublic())}
        for host, port in self.known_nodes.items():#loop through all known nodes
            connected_node = self.connect_with_node(host, port)
            connected_node.busy = True
            self.send_to_node(connected_node, data)
            response = self.getResponse(connected_node)
            balance = response["BALANCE"]
            if balance is not None:
                cnt[balance] += 1
        return cnt.most_common()[0][0]#return most common balance

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User Client Script")#create arguments
    parser.add_argument("-p", help="Wallet Private File", default=os.environ["HOME"]+"/.pksa/pksa_rsa.pem", dest="path")
    parser.add_argument("--amount", help="Make transaction", type=float, dest="amount")
    parser.add_argument("--receiver", help="Receiver wallet - exponential:modulus", dest="receiver")
    parser.add_argument("--fee", help="Fee for miners", type=float, dest="fee")
    parser.add_argument("--new", help="Create New Wallet", default=False, dest="new", action="store_true")
    parser.add_argument("--balance", help="Get balance from Wallet", default=False, dest="balance", action="store_true")
    conf = vars(parser.parse_args())
    amount, path, new, receiver, fee, balance = conf["amount"], conf["path"], conf["new"], conf["receiver"], conf["fee"], conf["balance"]
    wallet = Wallet()
    if new:
        write_path = input("Default path: ~/.pksa/pksa_rsa.pem")
        if write_path == "": 
            write_path = os.environ["HOME"]+"/.pksa/pksa_rsa.pem"
        wallet.storeKey(write_path)
    else:
        wallet.openKey(path)
    if balance:
        node = UserP2P('127.0.0.1', 8999, known_host, known_port, wallet)
        print("[*] User Balance: {0}".format(node.getBalance()))
    elif amount is not None and receiver is not None and fee is not None:
        receiver = tuple(int(comp) for comp in receiver.split(":"))
        node = UserP2P('127.0.0.1', 8999, known_host, known_port, wallet)
        node.createTransaction(receiver, amount, fee)
