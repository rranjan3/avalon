# !/usr/bin/python3

import argparse
import asyncio
import json
import os
import web3
from urllib.parse  import urlparse

LISTENER_SLEEP_DURATION = 5 # seconds
PROVIDERS = {
    'http':  web3.HTTPProvider,
    'https': web3.HTTPProvider,
    'ipc':   web3.IPCProvider,
    'ws':    web3.WebsocketProvider,
    'wss':   web3.WebsocketProvider,
}



class BlockchainInterface:
    def __init__(self, gateway):
        self.provider = web3.Web3(PROVIDERS[urlparse(gateway).scheme](gateway))
        # TODO: store list of contracts?
    def newAccount(self, pk):
        return web3.Account.privateKeyToAccount(pk)
    def newContract(self, file, address):
        return self.provider.eth.contract(address=address, abi=json.load(open(file)).get('abi'), ContractFactoryClass=web3.contract.Contract)
    def newListener(self, contract, event, fromBlock='latest'):
        return contract.events[event].createFilter(fromBlock=fromBlock)



class EventProcessor:
    async def listener(self, eventListener):
        while True:
            for event in eventListener.get_new_entries():
                await self.queue.put(event)
                print("Evt pushed into Q")
            await asyncio.sleep(LISTENER_SLEEP_DURATION)

    async def handler(self, callback, *kargs, **kwargs):
        while True:
            event = await self.queue.get()
            print("Popped event from Q")
            callback(event, *kargs, **kwargs)
            self.queue.task_done()

    async def start(self, eventListener, callback, *kargs, **kwargs):
        self.queue = asyncio.Queue()
        loop = asyncio.get_event_loop()
        self.listeners = [ loop.create_task(self.listener(eventListener)) for _ in range(1) ]
        self.handlers  = [ loop.create_task(self.handler(callback, *kargs, **kwargs))       for _ in range(8) ]

        """self.queue = asyncio.Queue()
        self.listeners = [ asyncio.create_task(self.listener(eventListener))             for _ in range(1) ]
        self.handlers  = [ asyncio.create_task(self.handler(callback, *kargs, **kwargs)) for _ in range(8) ]"""
        await asyncio.gather(*self.listeners) # infinite loop
        await self.queue.join() # this code should never run
        await self.stop() # this code should never run

    async def stop(self):
        for process in self.listeners: process.cancel()
        for process in self.handlers:  process.cancel()
        print("---exit---")



def handleEvent(event, account, contract):
    """arg_from  = event.args.get('from')
    arg_to    = event.args.get('to')
    arg_value = event.args.get('value')
    print(f'handler got event Transfer {arg_from} -> {arg_to} : {arg_value}')"""
    print(f'Event ---> {event}')
    # DO SOMETHING HERE!
    # → How to execute a view call
    # contract.functions.myview(<some args>)..call()
    # → How to send a transaction
    # contract.functions.mymethod(<some args>).transact({ 'from': account.address })



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--gateway',  type=str, default='http://localhost:8545')
    parser.add_argument('--contract', type=str, default='build/contracts/erc20.json')
    parser.add_argument('--event',    type=str, default='Transfer')
    parser.add_argument('--address',  type=str, default='0x0000000000000000000000000000000000000000')
    parser.add_argument('--pk',       type=str, default='')
    config = parser.parse_args()

    w3 = BlockchainInterface(config.gateway)

    account  = w3.newAccount(config.pk)
    contract = w3.newContract(config.contract, config.address)
    listener = w3.newListener(contract, config.event)

    try:
        daemon = EventProcessor()
        asyncio.get_event_loop().run_until_complete(daemon.start(
            listener,
            handleEvent,
            account=account,
            contract=contract,
        ))
    except KeyboardInterrupt:
        asyncio.get_event_loop().run_until_complete(daemon.stop())

