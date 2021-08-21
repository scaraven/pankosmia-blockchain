#!/usr/bin/env python3
import base64
import hashlib
import json
import time
import sys
import wallet
from miner import Miner


class Blockchain():
    'Basic Blockchain class'
    def __init__(self, valid_size=5):
        #This decides how many blocks needed to be added to resolve a conflict
        self.valid_size = valid_size

        #Dictionary which stores block_hash:block class for all added blocks
        self.blockchain = {}
        #Dictionary which stores block_hash:[child_hash#1, child_hash#2, ..., child_hash#n]
        self.children = {}
        #Set which contains block_hash for any block which has had a resolved conflict (and hence cannot have anymore conflicts)
        self.resolved = set()

        #Add genesis block
        self.children["0"*64] = []

        self.ledger = TransactionLedger()
    #This adds a block
    def addBlock(self, block):
        if block.verifyPoW() and block.verifyHeader():
            block_info = block.getBlock()
            prevHash = block_info["prevHash"]
            if (prevHash in self.blockchain.keys() or prevHash == "0"*64) \
             and prevHash not in self.resolved:
                self.blockchain[block.getHash()] = block
                self.children[block.getHash()] = []
                self.children[prevHash].append(block.getHash())
                self.resolveConflict(block.getHash())
                return True
            else:
                if prevHash in self.resolved:
                    print("Cannot add to blockchain due to resolved block")
                else:
                    print("Cannot add to blockchain due to non-existant parent") 
        else:
            print("Block is not verified")
        return False
    #Resolve any fixable conflicts after each block is added
    def resolveConflict(self, pointer):
        genesisReached = False
        iteration = 0
        while iteration < self.valid_size and not genesisReached:
            child = pointer
            pointer = self.blockchain[pointer].getBlock()["prevHash"]

            #We stop iterating if we reach the genesis block
            if pointer == "0"*64:
                genesisReached = True
            iteration += 1
                
        if pointer not in self.resolved and not genesisReached:
            if not self.verifyTransactions(pointer):
                self.removeChain(pointer)
            else:
                self.updateLedger(pointer)
                self.resolved.add(pointer)
                if len(self.children[pointer]) > 1:
                    for block_hash in self.children[pointer]:
                        if child != block_hash:
                            self.removeChain(block_hash)
    def updateLedger(self, pointer):
        if pointer != "0"*64:
            block = self.blockchain[pointer]
            for transaction in block.getTransactions().values():
                self.ledger.addTransaction(transaction)
        self.ledger.rewardMiner(block)
    def verifyTransactions(self, pointer):#prevent transaction smuggling
        #block of type Block Class
        block = self.blockchain[pointer]
        transactions = block.transactions
        for transaction_hash, transaction in transactions.items():
            sender = transaction.info["sender"]
            self.ledger.addTransaction(transaction)
            if self.ledger.getBalance(sender) < 0.0:
                self.ledger.removeTransaction(transaction)
                return False
        return True
    #Use recursion to remove blocks
    def removeChain(self, block_hash):
        print("Removing block {0}".format(block_hash))
        if len(self.children[block_hash]) != 0:
            for child_block_hash in self.children[block_hash]:
                self.removeChain(child_block_hash)
        del self.blockchain[block_hash]
        del self.children[block_hash]

    #Getters and Setters
    def getBlock(self, block_hash):
        return self.blockchain[block_hash]
    def getBlockChain(self):
        return self.blockchain
    def returnTrustedBlock(self):
        return self.resolved
    def saveBlockchain(self, path):
        persist_blockchain = b64EncodeDictionary({block_hash: block.saveBlock() for block_hash, block in self.blockchain.items()})
        with open(path, "w") as fp:
            fp.write(persist_blockchain)
    def openBlockchain(self, path):
        self.__init__(valid_size=self.valid_size)
        with open(path, "r") as fp:
            persist_blockchain = b64DecodeDictionary(fp.read())
        for block_hash, block_encoded in persist_blockchain.items():
            block = Block()
            block.openBlock(block_encoded, self.ledger)
            #Create tests and verification?
            #It needs to be decided whether saved blockchain files need to be saved
            self.addBlock(block)
class Block():
    'Basic block for transactions'
    def __init__(self, prevHash=None, zeros=3):
        self.limit = 10
        self.transactions = {}
        self.zeros = zeros
        self.block = {"prevHash":prevHash, "transactions":list(self.transactions.keys()), "timestamp":time.time(), "PoW":0, "zeros":self.zeros, "miner":""}
        self.hash = ""
    def addTransaction(self, transaction):
        #Limit number of transactions per block
        if len(self.transactions) < self.limit:
            if transaction.verifyTransaction() and transaction.preventOverSpending() and transaction.verifyHeader():
                self.transactions[transaction.getSignature()] = transaction
                self.block["transactions"] = list(self.transactions.keys())
    #Computes hash of own block
    def computeHash(self):
        hasher = hashlib.sha256()
        dump = json.dumps(self.block).encode("utf-8")
        hasher.update(dump)
        nextHash = hasher.digest().hex()
        return nextHash
    def verifyHeader(self):
        info = self.block
        known_keys = ["prevHash", "transactions", "timestamp", "PoW", "zeros", "miner"]
        if len(info) != len(known_keys):#make sure we have the correct number of headers
            return False
        for inf, key in zip(info.keys(), known_keys):#Make sure the headers match
            if inf != key:
                return False
        for transaction_hash, key in zip(self.transactions.keys(), info["transactions"]):
            if transaction_hash != key:
                return False
        if len(self.transactions) > 10:
            return False
        return True#All checks have been passed, return true
    #Verifies a blockchain with its PoW
    def verifyPoW(self, proof=None):
        if proof != None:
            self.setPoW(proof)
        nextHash = self.computeHash()
        #Checks whether nextHash is valid
        if nextHash[0:self.zeros] == "0"*self.zeros:
            self.hash = nextHash
            return True
        else:
            return False
    #Getters and Setters
    def getBlock(self):
        return self.block
    def setPoW(self, proof):
        self.block["PoW"] = proof
    def setBlock(self, block):
        temp = self.block
        self.block = block

        if block.keys() != ["prevHash", "transactions", "timestamp", "PoW", "zeros"] or not verifyPoW():
            print("Invalid block template")
            self.block = temp
    def getHash(self):
        return self.hash
    def getTransactions(self):
        return self.transactions
    def saveBlock(self):
        persist_transactions = {header: txn.persistTxn() for header, txn in self.transactions.items() }#persist all the transactions
        persist = b64EncodeDictionary([self.block, persist_transactions])
        return persist
    def openBlock(self, encoded, ledger):#get encoded data and convert to block information
        persist = b64DecodeDictionary(encoded)#
        self.block, persist_transactions = persist
        transactions = {}
        for header, txn_data in persist_transactions.items():
            txn = wallet.NodeTransaction(None, None, None, isempty=True)
            txn.openTxn(txn_data, ledger)
            assert int(header) == txn.getSignature(), "Signature and Header mismatch"
            transactions[header] = txn
        self.transactions = transactions
class TransactionLedger():
    'Ledger of all trusted transactions for lookup'
    def __init__(self):

        #Data structure type: Data value type
        #dict: float
        self.ledger = {}
        #set: transaction_hashes
        self.pool = set()
    def addTransaction(self, transaction):
        info = transaction.getInfo()
        id_sender = self.computeHash(info["sender"])
        id_receiver = self.computeHash(info["receiver"])
        if id_sender not in self.ledger.keys():
            self.ledger[id_sender] = 0.0
        if id_receiver not in self.ledger.keys():
            self.ledger[id_receiver] = 0.0
        self.ledger[id_sender] -= (info["amount"] + info["fee"])
        self.ledger[id_receiver] += info["amount"]
        self.pool.add(transaction.getSignature())
    def removeTransaction(self, transaction):#This is to prevent transaction smuggling and should never be used to actually remove transactions
        info = transaction.getInfo()
        id_sender = self.computeHash(info["sender"])
        id_receiver = self.computeHash(info["receiver"])
        if transaction.getSignature() not in self.pool:
            return False
        if id_sender not in self.ledger.keys() or id_receiver not in self.ledger.keys():
            return False
        self.ledger[id_sender] += (info["amount"] + info["fee"])
        self.ledger[id_receiver] -= info["amount"]
        self.pool.remove(transaction.getSignature())
    def rewardMiner(self, block):
        reward = 5 #THIS IS A CONSTANT!
        miner = block.getBlock()["miner"]
        id_miner = self.computeHash(miner)
        if id_miner not in self.ledger.keys():
            self.ledger[id_miner] = 0.0
        for transaction in block.getTransactions().values():
            info = transaction.getInfo()
            self.ledger[id_miner] += info["fee"]
        self.ledger[id_miner] += reward
 
    def computeHash(self, list_key):
        hasher = hashlib.sha256()
        dump = json.dumps(list_key).encode("utf-8")
        hasher.update(dump)
        nextHash = hasher.digest().hex()
        return nextHash
    #Getters and Setters
    def getBalance(self, public_key):
        id = self.computeHash(public_key)
        if id in self.ledger.keys():
            return self.ledger[id]
        else:
            return None

def b64EncodeDictionary(data):
    return base64.b64encode(json.dumps(data).encode("ascii")).decode("ascii")
def b64DecodeDictionary(data):
    return json.loads(base64.b64decode(data.encode("ascii")).decode("ascii"))

def addBlock(blockchain, prevHash):
    block = Block(prevHash=prevHash)
    miner = Miner(block)
    miner.mine()
    blockchain.addBlock(block)
    return block.getHash()


def test_chain():
    print("First valid block")
    block_hash = addBlock(blockchain, "0"*64)
    print("\nFirst invalid block")
    invalid_hash = addBlock(blockchain, "0"*64)
    print("\nSecond valid block")
    block_hash = addBlock(blockchain, block_hash)
    print("\nSecond invalid block")
    invalid_hash = addBlock(blockchain, invalid_hash)
    print("\nThird valid block")
    block_hash = addBlock(blockchain, block_hash)
    print("\nFourth valid block")
    addBlock(blockchain, block_hash)
    print(blockchain.getBlockChain().keys())
    print(len(blockchain.getBlockChain().keys()))
def test2_chain():
    #test_chain()
    user1 = wallet.Wallet(blockchain, ledger)
    user2 = wallet.Wallet(blockchain, ledger)
    t1 = wallet.P2PTransaction(user1, user2, 10, time.time(), ledger)
    t2 = wallet.P2PTransaction(user2, user1, 5, time.time(), ledger)
    block = Block(prevHash="0"*64)
    block.addTransaction(t1)
    block.addTransaction(t2)
    miner = Miner(block)
    miner.mine()
    blockchain.addBlock(block)
    print(blockchain.getBlockChain())

if __name__ == "__main__":
    blockchain = Blockchain(valid_size=3)
    ledger = blockchain.ledger
    mineruser = wallet.Wallet(blockchain, ledger)
    initialBlock = Block(prevHash="0"*64)
    user1 = wallet.Wallet(blockchain, ledger)
    user2 = wallet.Wallet(blockchain, ledger)
    miner = Miner(initialBlock, mineruser, ledger)
    blockchain.addBlock(initialBlock)
    blockchain.updateLedger(initialBlock.getHash())
    info = {"sender": mineruser.getPublic(), "receiver":user1.getPublic(), "amount":2, "timestamp":time.time(), "fee":1}
    t1 = wallet.NodeTransaction(info, mineruser.signTransaction(info)[0], ledger)
    secondBlock = Block(initialBlock.getHash())
    secondBlock.addTransaction(t1)
    miner = Miner(secondBlock, user2, ledger)
    blockchain.addBlock(secondBlock)
    blockchain.updateLedger(secondBlock.getHash())
    print("Miner User Balance - {0}".format(mineruser.getBalance()))
    print("User1 Balance - {0}".format(user1.getBalance()))
    print("User2 Balance - {0}".format(user2.getBalance()))

    
    




