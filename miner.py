#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from wallet import *
import json

class Miner():
    'Miner classes which finds PoW for Blocks'
    def __init__(self, Block, miner):
        self.Block = Block
        self.Block.block["miner"] = miner.getPublic()
        self.mine()

    #Increments PoW and then checks whether that hash works
    def mine(self):
        found = False       
        proof = 0
        while not found:
            if self.Block.verifyPoW(proof=proof):
                self.Block.setPoW(proof)
                print(self.Block.getHash())
                found = True
            else:
                proof +=1

if __name__ == "__main__":
    startup()
