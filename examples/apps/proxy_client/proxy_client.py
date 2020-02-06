#! /usr/bin/env python3

# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import json
import argparse
import logging
import secrets

import config.config as pconfig
import utility.logger as plogger
import crypto_utils.crypto_utility as utility
from avalon_client_sdk.utility.tcf_types import WorkerType
import avalon_client_sdk.worker.worker_details as worker_details
from avalon_client_sdk.work_order.work_order_params import WorkOrderParams
from avalon_client_sdk.direct.avalon_direct_client \
    import AvalonDirectClient
from error_code.error_status import WorkOrderStatus, ReceiptCreateStatus
import crypto_utils.signature as signature
from error_code.error_status import SignatureStatus
from avalon_client_sdk.work_order_receipt.work_order_receipt_request \
    import WorkOrderReceiptRequest
from web3 import Web3, HTTPProvider
import socket

# Remove duplicate loggers
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logger = logging.getLogger(__name__)
TCFHOME = os.environ.get("TCF_HOME", "../../")


def ParseCommandLine(args):

    global worker_obj
    global worker_id
    global workload_id
    global in_data
    global config
    global mode
    global uri
    global address
    global show_receipt
    global show_decrypted_output
    global requester_signature

    parser = argparse.ArgumentParser()
    mutually_excl_group = parser.add_mutually_exclusive_group()
    parser.add_argument(
        "-c", "--config",
        help="The config file containing the Ethereum contract information",
        type=str)
    mutually_excl_group.add_argument(
        "-u", "--uri",
        help="Direct API listener endpoint, default is http://localhost:1947",
        default="http://localhost:1947",
        type=str)
    mutually_excl_group.add_argument(
        "-a", "--address",
        help="an address (hex string) of the smart contract " +
        "(e.g. Worker registry listing)",
        type=str)
    parser.add_argument(
        "-m", "--mode",
        help="should be one of listing or registry (default)",
        default="registry",
        choices={"registry", "listing"},
        type=str)
    parser.add_argument(
        "-w", "--worker_id",
        help="worker id (hex string) to use to submit a work order",
        type=str)
    parser.add_argument(
        "-l", "--workload_id",
        help='workload id (hex string) for a given worker',
        type=str)
    parser.add_argument(
        "-i", "--in_data",
        help='Input data',
        nargs="+",
        type=str)
    parser.add_argument(
        "-r", "--receipt",
        help="If present, retrieve and display work order receipt",
        action='store_true')
    parser.add_argument(
        "-o", "--decrypted_output",
        help="If present, display decrypted output as JSON",
        action='store_true')
    parser.add_argument(
        "-rs", "--requester_signature",
        help="Enable requester signature for work order requests",
        action="store_true")
    options = parser.parse_args(args)

    if options.config:
        conf_files = [options.config]
    else:
        conf_files = [TCFHOME +
                      "/client_sdk/avalon_client_sdk/tcf_connector.toml"]
    confpaths = ["."]
    try:
        config = pconfig.parse_configuration_files(conf_files, confpaths)
        json.dumps(config)
    except pconfig.ConfigurationException as e:
        logger.error(str(e))
        sys.exit(-1)

    mode = options.mode

    uri = options.uri
    if uri:
        config["tcf"]["json_rpc_uri"] = uri

    address = options.address
    if address:
        if mode == "listing":
            config["ethereum"]["direct_registry_contract_address"] = \
                address
        elif mode == "registry":
            logger.error(
                "\n Only Worker registry listing address is supported." +
                "Worker registry address is unsupported \n")
            sys.exit(-1)

    worker_id = options.worker_id

    workload_id = options.workload_id
    if not workload_id:
        logger.error("\nWorkload id is mandatory\n")
        sys.exit(-1)

    in_data = options.in_data
    show_receipt = options.receipt
    show_decrypted_output = options.decrypted_output
    requester_signature = options.requester_signature

def submit_work_order( work_order_id, worker_id, requester_id, request):
    # 0x2132FB999Cf6De74E98752Cc1424bd99AFB01D52
    # contract.functions.mymethod(<some args>).transact({ 'from': account.address })
    contract_address     = '0x2525fef0dE3454e05b37F040d2f4862C3460f2E6'
    wallet_private_key   = 'c3260c27a1231a697cd0691b62ca534930aba138e044ed53fcdb22e24ac4d56c'
    wallet_address       = '0xefb21e451a2f8c9e25e02ffee969b169a067d343'
    w3 = Web3(HTTPProvider('http://10.66.245.80:8545/'))
    logger.info("Connection established : "+str(w3.isConnected()))
    contractDetails   = json.load(open("WorkOrderRegistry.json"))
    contract = w3.eth.contract(address = contract_address, abi = contractDetails.get('abi'))

    #return contract.functions.workOrderSubmit(Web3.toBytes(hexstr=work_order_id), "worker_id".encode("UTF-8"), Web3.toBytes(hexstr=requester_id), _workOrderRequest=request).transact({ 'from': Web3.toChecksumAddress(wallet_address) })
    
    nonce = w3.eth.getTransactionCount(Web3.toChecksumAddress(wallet_address))
    logger.info("balance =  "+str(w3.eth.getBalance(Web3.toChecksumAddress(wallet_address))));
    txn_dict = contract.functions.workOrderSubmit(Web3.toBytes(hexstr=work_order_id), "worker_id".encode("UTF-8"), Web3.toBytes(hexstr=requester_id), _workOrderRequest=request).buildTransaction({
        'chainId': 3,
        'gas': 3000000,
        'gasPrice': w3.toWei('40', 'gwei'),
        'nonce': nonce,
    })

    signed_txn = w3.eth.account.signTransaction(txn_dict, private_key=wallet_private_key)

    result = w3.eth.sendRawTransaction(signed_txn.rawTransaction)

    tx_receipt = w3.eth.waitForTransactionReceipt(result)

    logger.info(tx_receipt)

    if tx_receipt is None:
        return {'status': 'failed', 'error': 'timeout'}

    processed_receipt = contract.events.workOrderSubmitted().processReceipt(tx_receipt)

    logger.info(processed_receipt)


def Main(args=None):
    ParseCommandLine(args)

    config["Logging"] = {
        "LogFile": "__screen__",
        "LogLevel": "INFO"
    }

    plogger.setup_loggers(config.get("Logging", {}))
    sys.stdout = plogger.stream_to_logger(
        logging.getLogger("STDOUT"), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(
        logging.getLogger("STDERR"), logging.WARN)

    logger.info("***************** TRUSTED COMPUTE FRAMEWORK (TCF)" +
                " *****************")

    global direct_jrpc
    direct_jrpc = AvalonDirectClient(config_file=None, config=config)

    global address
    if mode == "registry" and address:
        logger.error("\n Worker registry contract address is unsupported \n")
        sys.exit(-1)

    # Connect to registry list and retrieve registry
    global uri
    if not uri and mode == "listing":
        registry_list_instance = direct_jrpc.get_worker_registry_list_instance(
        )
        # Lookup returns tuple, first element is number of registries and
        # second is element is lookup tag and
        # third is list of organization ids.
        registry_count, lookup_tag, registry_list = \
            registry_list_instance.registry_lookup()
        logger.info("\n Registry lookup response: registry count: {} " +
                    "lookup tag: {} registry list: {}\n".format(
                        registry_count, lookup_tag, registry_list))
        if (registry_count == 0):
            logger.error("No registries found")
            sys.exit(1)
        # Retrieve the fist registry details.
        registry_retrieve_result = registry_list_instance.registry_retrieve(
            registry_list[0])
        logger.info("\n Registry retrieve response: {}\n".format(
            registry_retrieve_result
        ))
        config["tcf"]["json_rpc_uri"] = registry_retrieve_result[0]

    # Prepare worker
    req_id = 31
    global worker_id
    if not worker_id:
        worker_registry_instance = direct_jrpc.get_worker_registry_instance()
        worker_lookup_result = worker_registry_instance.worker_lookup(
            worker_type=WorkerType.TEE_SGX, id=req_id
        )
        logger.info("\n Worker lookup response: {}\n".format(
            json.dumps(worker_lookup_result, indent=4)
        ))
        if "result" in worker_lookup_result and \
                "ids" in worker_lookup_result["result"].keys():
            if worker_lookup_result["result"]["totalCount"] != 0:
                worker_id = worker_lookup_result["result"]["ids"][0]
            else:
                logger.error("ERROR: No workers found")
                sys.exit(1)
        else:
            logger.error("ERROR: Failed to lookup worker")
            sys.exit(1)

    req_id += 1
    worker_retrieve_result = worker_registry_instance.worker_retrieve(
        worker_id, req_id
    )
    logger.info("\n Worker retrieve response: {}\n".format(
        json.dumps(worker_retrieve_result, indent=4)
    ))

    if "error" in worker_retrieve_result:
        logger.error("Unable to retrieve worker details\n")
        sys.exit(1)

    # Initializing Worker Object
    worker_obj = worker_details.SGXWorkerDetails()
    worker_obj.load_worker(worker_retrieve_result)

    logger.info("**********Worker details Updated with Worker ID" +
                "*********\n%s\n", worker_id)

    # Convert workloadId to hex
    global workload_id
    workload_id = workload_id.encode("UTF-8").hex()
    work_order_id = secrets.token_hex(16)
    requester_id = secrets.token_hex(16)
    logger.info("+++++++++++++++++++"+workload_id+"+++++++++++"+work_order_id+"++++++++++++"+requester_id)
    session_iv = utility.generate_iv()
    session_key = utility.generate_key()
    requester_nonce = secrets.token_hex(16)
    # Create work order
    wo_params = WorkOrderParams(
        work_order_id, worker_id, workload_id, requester_id,
        session_key, session_iv, requester_nonce,
        result_uri=" ", notify_uri=" ",
        worker_encryption_key=worker_obj.encryption_key,
        data_encryption_algorithm="AES-GCM-256"
    )
    # Add worker input data
    global in_data

    for value in in_data:
        wo_params.add_in_data(value)

    # Encrypt work order request hash
    wo_params.add_encrypted_request_hash()

    private_key = utility.generate_signing_keys()
    if requester_signature:
        # Add requester signature and requester verifying_key
        if wo_params.add_requester_signature(private_key) is False:
            logger.info("Work order request signing failed")
            exit(1)
    # Submit work order
    logger.info("Work order submit request : %s, \n \n ",
                wo_params.to_jrpc_string(req_id))
    work_order_instance = direct_jrpc.get_work_order_instance()
    req_id += 1
    ret_code = submit_work_order(
        wo_params.get_work_order_id(),
        wo_params.get_worker_id(),
        wo_params.get_requester_id(),
        wo_params.to_string()
    )
    logger.info("Work order submit response : {}\n ".format(
        ret_code
    ))

# -----------------------------------------------------------------------------
Main()

