#!/usr/bin/env python3
from Crypto.PublicKey import RSA
import json
from hashlib import sha256
import time

class Wallet():
    def __init__(self, blockchain, ledger):
        self.__keyPair__ = RSA.generate(bits=1024)
        self.blockchain = blockchain
        self.ledger = ledger
    def getPublic(self):
        return self.__keyPair__.e, self.__keyPair__.n
    def setKey(self, keyPair):
        assert isintance(keyPair, type(self.__keyPair__)), "Invalid KeyPair type"
        self.__keyPair__ = keyPair
    def signTransaction(self, transaction):
        hash = int.from_bytes(sha256(json.dumps(transaction).encode("utf-8")).digest(), byteorder='big')
        return pow(hash, self.__keyPair__.d, self.__keyPair__.n), hash
    def storeKey(self, path):
        with open(path, "w") as fp:
            fp.write(self.__keyPair__.export_key('PEM'))
    def getBalance(self):
        return self.ledger.getBalance(self.getPublic())

def signTransaction(transaction, d_key, n_key):
        hash = int.from_bytes(sha256(json.dumps(transaction).encode("utf-8")).digest(), byteorder='big')
        return pow(hash, d_key, n_key), hash

class Transaction():
    def __init__(self, sender, receiver, amount, timestamp, ledger, fee):
        self.ledger = ledger
        senderKey = sender.getPublic()
        receiverKey = receiver.getPublic()
        self.info = {"sender":senderKey, "receiver":receiverKey, "amount":amount, "timestamp":timestamp, "fee":fee}
        self.signature, self.hash = sender.signTransaction(self.info)

    #Prevents a sender from spending more money than they have
    #Prevents a transaction from being faked - Done
    def verify_transaction(self):
        hashFromSignature = pow(self.signature, *self.info["sender"])
        return hashFromSignature == self.hash

    def preventOverSpending(self):
        balance =  self.ledger.getBalance(self.info["sender"])
        if balance >= (self.info["amount"] + self.info["fee"]):
            return True
        else:
            return False

    #Getters and Setters
    def getInfo(self):
        return self.info
    def getSignature(self):
        return self.signature

if __name__ == "__main__":
    user1 = Wallet()
    user2 = Wallet()

    t1 = Transaction(user1, user2, 50)
    print(t1.verify_transaction())
    print(t1.preventOverSpending(50))


