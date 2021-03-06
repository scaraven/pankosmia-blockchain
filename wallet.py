#!/usr/bin/env python3
import base64
from Crypto.PublicKey import RSA
import json
from hashlib import sha256
import time

class Wallet():
    def __init__(self):
        self.__keyPair__ = RSA.generate(bits=1024)
    def getPublic(self):
        return self.__keyPair__.e, self.__keyPair__.n
    def setKey(self, keyPair):
        assert isinstance(keyPair, type(self.__keyPair__)), "Invalid KeyPair type"
        self.__keyPair__ = keyPair
    def signTransaction(self, transaction):
        hash = int.from_bytes(sha256(json.dumps(transaction).encode("utf-8")).digest(), byteorder='big')
        return pow(hash, self.__keyPair__.d, self.__keyPair__.n), hash
    def storeKey(self, path):
        with open(path, "wb") as fp:
            fp.write(self.__keyPair__.export_key('PEM'))
    def openKey(self, path):
        with open(path, "rb") as fp:
            self.__keyPair__ = RSA.import_key(fp.read())
    def getBalance(self):#OBSELETE
        return self.ledger.getBalance(self.getPublic())

def signTransaction(transaction, d_key, n_key):
        hash = int.from_bytes(sha256(json.dumps(transaction).encode("utf-8")).digest(), byteorder='big')
        return pow(hash, d_key, n_key), hash

class BaseTransaction():#this is to be used when a transaction class is being instantiated by someome other than the sender wallet
    def __init__(self, info, signature):
        self.info = info
        #generate transaction hash
        _, self.hash = signTransaction(info, 1, 1)
        self.signature = signature
        #verify transactions
        if not self.verifyTransaction():
            raise ValueError("Transaction Signature is not Valid")
        if not self.verifyHeader():
            raise ValueError("Transaction Header is not Valid")
    #verification transactions
    def verifyTransaction(self):
        #generate hash
        _, self.hash = signTransaction(self.info, 1, 1)
        #derive hash from signature
        hashFromSignature = pow(self.signature, *self.info["sender"])
        return hashFromSignature == self.hash
    def verifyHeader(self):
        #valid headers
        headers = ["sender", "receiver", "amount", "timestamp", "fee"]
        if len(headers) != len(self.info.keys()):
            return False#header length does not match
        for header, key in zip(headers, self.info.keys()):
            if header != key:
                return False#header values does not match
        return True

    #Getters and Setters
    def getInfo(self):
        return self.info
    def getSignature(self):
        return self.signature
class UserTransaction(BaseTransaction):
    """UserTransaction inherits from the BaseTransaction class
    it is to be instantiated by a wallet which is able to access the transaction signing function"""
    def __init__(self, sender_key, receiver_key, amount, fee, signfunc):
        #construct transaction
        info = {"sender": sender_key, "receiver":receiver_key, "amount":amount, "timestamp":time.time(), "fee":fee}
        #generate signature and hash
        self.signature, self.hash = signfunc(info)
        #call BaseTransaction constructor
        super(UserTransaction, self).__init__(info, self.signature)
class NodeTransaction(BaseTransaction):
    """NodeTransaction is a child class of BaseTransaction
    It should only be instantiated by a node"""
    def __init__(self, info, signature, ledger, isempty=False):
        #checks whether this is a empty template for a transaction
        if not isempty:
            super(NodeTransaction, self).__init__(info, signature)
            self.ledger = ledger
    #encode the transaction information in base64
    def persistTxn(self):
        persist = b64EncodeDictionary([self.info, self.signature])
        return persist
    #decode encoded transaction. This modifies the transaction information 
    #so should only be used when the transaction instance is empty
    def openTxn(self, encoded, ledger):
        info, signature = b64DecodeDictionary(encoded)
        info["sender"] = tuple(info["sender"])
        info["receiver"] = tuple(info["receiver"])
        self.__init__(info, signature, ledger)
    #prevents user from spending too much
    def preventOverSpending(self):
        balance = self.ledger.getBalance(self.info["sender"])
        if balance >= (self.info["amount"] + self.info["fee"]):
            return True
        else:
            return False 
def b64EncodeDictionary(data):
    return base64.b64encode(json.dumps(data).encode("ascii")).decode("ascii")
def b64DecodeDictionary(data):
    return json.loads(base64.b64decode(data.encode("ascii")).decode("ascii"))

if __name__ == "__main__":
    user1 = Wallet()
    user2 = Wallet()

    t1 = Transaction(user1, user2, 50)
    print(t1.verify_transaction())
    print(t1.preventOverSpending(50))


