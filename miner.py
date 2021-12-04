#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from wallet import *
import json

class Miner():
    'Miner classes which finds PoW for Blocks'
    def __init__(self, Block, miner):
        self.Block = Block
        self.Block.block["miner"] = miner.getPublic()#modify miner entry in the block
        self.mine()

    #Increments PoW and then checks whether that hash works
    def mine(self):
        found = False       
        proof = 0#start at 0
        while not found:#keep on looping until found is true
            if self.Block.verifyPoW(proof=proof):#check proof of work
                self.Block.setPoW(proof)#our proof is valid so we can modify the block
                print(self.Block.getHash())
                found = True
            else:#if the proof is wrong, increment the value
                proof +=1
