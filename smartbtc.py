#!/usr/bin/env python3
# SmartBTC
# ** bitcointransactions with pkcs11-smartcard **
# version: 4 sept 2016
# author:  J.v.d.Bosch
#
# SmartBTC is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or
# any later version.  See: http://www.gnu.org/licenses/gpl-3.0.html
#
# SmartBTC is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
#
# Versionhistory:
# first version 4 sept 2016
# 12 jan 2017: added pyc.setopt(pycurl.USERAGENT, "Mozilla/5.0") ... tot prevent webserver-access-error
#
#
# uses python-bitcoinlib
# Bitcoinvalues are in mBTC

import os, sys, re
import json, tempfile, struct
import datetime, pycurl, io
from io import BytesIO
from tkinter import Tk, Toplevel, Label, Entry, Button, StringVar, N, W, S, E
from tkinter import ttk, messagebox, PhotoImage, END
from os.path import expanduser
import subprocess, hashlib, getpass
from hashlib import sha256
import base64, binascii

import bitcoin
from bitcoin import SelectParams
from bitcoin.core import b2x, x, lx, COIN, COutPoint, CMutableTxOut
from bitcoin.core import CMutableTxIn, CMutableTransaction
from bitcoin.core import Hash160, ValidationError
from bitcoin.core.script import SignatureHash, SIGHASH_ALL
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY
from bitcoin.core.script import OP_CHECKSIG
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.core.scripteval import VerifySignature, VerifySignatureError
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from bitcoin.core.key import CECKey, CPubKey

#### SET THIS TO THE FULL PATH OF THE OPENSC-PKCS11 LIBRARY
p11module = "/usr/local/lib/opensc-pkcs11.so"

# set to 1 for debug information
debug = 1

# a global variable for the items from the configurationfile
confDict = {}
homedir = os.getenv('HOME')

# secp256k1 parameter
orderN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def Err(msg):
    #
    # display Error, and exit
    #
    messagebox.showwarning("Error:", msg)
    exit(-1)


def Info(msg):
    #
    # display Info
    #
    messagebox.showwarning("Info:", msg)


def YesNo(msg):
    # window to ask yes or no
    yesno = messagebox.askquestion("Please Press Yes or No", msg)
    return yesno


class ConfDialog:
    # window asks to enter the configurationfile-id
    # file ~/.smartbtc/<cofiguration-id>.conf
    def __init__(self, parent):
        top = self.top = Toplevel(parent)
        top.title("Choose Configfile")
        top.lift()
        self.myLabel = Label(top,
                             text='***Enter configfile-id (without .conf):***')
        self.myLabel.pack()
        self.myEntryBox = Entry(top)
        self.myEntryBox.bind("<Return>", self.sendid)
        self.myEntryBox.pack()
        self.mySubmitButton = Button(top, text='Submit')
        self.mySubmitButton.bind("<Button-1>", self.sendid)
        self.mySubmitButton.pack()
        self.myEntryBox.focus_set()
        self.confid = ""

    def sendid(self, event):
        self.confid = self.myEntryBox.get()
        self.top.destroy()


def readConfig(id):
    #
    # read the configuration files
    # set appropriate defaults if possible
    #

    global confDict  # Dictionairy
    global homedir

    # global.conf
    conffile = homedir + "/" + ".smartbtc/" + "global.conf"

    try:
        conffile = open(conffile, "r")
        # read configuration in confDict key-value pairs
        for line in conffile.readlines():
            if not line.startswith('#') and ('=' in line):
                # split on first '=', strip off white spaces
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if (key):
                    confDict[key] = value

    except IOError:
        Err("Cannot open configfile")

    if 'Transactionfee' in confDict:
        fee = float(confDict['Transactionfee'])
    else:
        confDict['Transactionfee'] = 0.0

    if not ('Provider-Url-Testnet' in confDict):
        if not ('Provider-Url-Mainnet' in confDict):
            Err("No Provider-Url= in the config file")

    if not ('SendTx-Url-Testnet' in confDict):
        if not ('SendTx-Url-Mainnet' in confDict):
            Err("No SendTx-Url= in the config file")
    
    if 'MaxUnspentLines' in confDict:
        maxunspentlines = int(confDict['MaxUnspentLines'])
    else:
        confDict['MaxUnspentLines'] = 5

    if 'BTCtransactionsDir' in confDict:
        txdir = confDict['BTCtransactionsDir']
        if txdir.find(homedir) == -1:
            txdir = homedir + "/" + confDict['BTCtransactionsDir']
        try:
           os.stat(txdir)
        except:
           os.mkdir(txdir)
    else:
        Err('No BTCtransactionsDir= in the config file')


    # config files per key
    conffile = homedir + "/" + ".smartbtc/" + id + ".conf"

    try:
        conffile = open(conffile, "r")
        # read configuration in confDict key-value pairs
        for line in conffile.readlines():
            if not line.startswith('#') and ('=' in line):
                # split on first '=', strip off white spaces
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if (key):
                    confDict[key] = value

    except IOError:
        Err("Cannot open configfile")

    if 'Network' in confDict:
        network = confDict['Network']
        if ((network != 'mainnet') and (network != 'testnet')):
            Err('Networkname error in config-file, should be mainnet or testnet')
    else:
        Err('No Network= in config-file (should be mainnet testnet)')

    SelectParams(network)

    if 'Bitcoinaddress' in confDict:
        bitcoinAddress = confDict['Bitcoinaddress']
        if not (checkbtcaddr(bitcoinAddress)):
            Err('Bitcoinaddress error in config-file')

    if 'Key-ID' not in confDict:
        Err("No Key-ID= in config file")

    if 'Public-key' in confDict:
        pubkey = confDict['Public-key']
        if (len(pubkey) != 130):
            Err("Wrong public key length (!=130) in config-file")
        # check pubkey, first 2 bytes (in hex) should be: 04
        if (pubkey[0] != '0' or pubkey[1] != '4'):
            Err("Wrong public key in config file")
    else:
        Err('No Public-key= in the config file')

    if (debug):
        print(confDict)


def get_utxo(provider_unspent_url):
    #
    # get the Unspent Transaction Outputs (UTXO's)
    # and initialize amountfrom
    # returns:
    #     1) unspents as floats in mbtcval[txid:<vout>]
    #     2) empty list amountfrom

    bitcoinAddress = confDict['Bitcoinaddress']

    mbtcval = {}
    amountfrom = {}

    req = provider_unspent_url+"/"+bitcoinAddress

    # SOME CODE DEPENDS ON THE UNSPENT_URL_PROVIDER: (only needed for smartbit)
    if provider_unspent_url.find("smartbit") > 0:
        req = req + "/unspent" 
        smartbit = True
    else:
        smartbit = False

    if (debug):
        print ("unspent request:", req)

    buf = BytesIO()
    pyc = pycurl.Curl()
    pyc.setopt(pycurl.URL, req)
    pyc.setopt(pycurl.CONNECTTIMEOUT, 50)
    pyc.setopt(pycurl.FAILONERROR, True)
    pyc.setopt(pycurl.USERAGENT, "Mozilla/5.0 (X11; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0")
    pyc.setopt(pycurl.HTTPHEADER, ['Accept: text/html', 'Accept-Charset: UTF-8'])
    # Set the WRITEFUNCTION and point it to the write string buffer
    pyc.setopt(pyc.WRITEFUNCTION, buf.write)
    # catch the output
    try:
        pyc.perform()
    except IOError:
        Err("Network error, cannot request unspent data")

    respdata = buf.getvalue()
    buf.close()
    if (debug):
        print(respdata)

    # decode from bytes
    jsonobj = json.loads(respdata.decode())

    if (smartbit == False):
       # the provider unspent output should be in json format:
       #     {
       #       "data": {
       #            "unspent": [
       #                  { "amount":  0.00193371,
       #                    "confirmations": 43,
       #                    "n":1,
        jdata = jsonobj["data"]["unspent"]
        amountstr = 'amount'
        txstr = u'tx'
    else:   # smartbit has txid and value in json
       # the provider unspent output should be in json format:
       #     {
       #       "unspent": [
       #            { "value":  0.00193371,
       #               "confirmations": 43,
       #               "n":1,
        jdata = jsonobj["unspent"]
        amountstr = 'value'
        txstr = u'txid'

    for tx in jdata: 
        if (debug):
           print(tx)
        if amountstr in tx:
           mbtcvalue = tx[amountstr]
        else:
           if (debug):
               print("no amounts in unspent")
        if 'n' in tx:
           n = tx["n"]
        else:
           n = ""
           if (debug):
               print("no vout-number n in unspent")
        if 'confirmations' in tx:
           confi = tx["confirmations"]
           if confi < 6:
                # you should not really trust this unspent
                rg =  "r"   # display in red
           else:
                rg = "g"    # display in green
        # mbtcvalue is in btc, transform it in milli -btc
        txid = tx[txstr] + ":" + str(n) + rg
        mbtcvalue = float(mbtcvalue)*1000
        mbtcval[txid] = mbtcvalue
        if (debug):
            print(txid, "==>unspent value:", mbtcvalue)

    # init amountfrom
    for txid in mbtcval:
        amountfrom[txid] = 0.0

    if (debug):
        print(mbtcval)

    return mbtcval, amountfrom


def send_tx(network):
    #
    # Send Transaction tx (in hex) to the provider
    # blockr.io,smartbit:  curl -d '{"hex":"TX_HASH"}' http://btc.blockr.io/api/v1/tx/push
    # webbbtc.com: curl http://test.webbtc.com/relay_tx.json -X \
    #                     POST -d "wait=10&tx=<TX_IN_HEX>"

    try:
        with open(txfilename.get(), "r") as fin:
            tx_hex = fin.readline()
        fin.close()
    except IOError:
        Err('Cannot read transaction file')

    if (network == 'testnet'):
        sendtx_url = confDict['SendTx-Url-Testnet']
    if (network == 'mainnet'):
        sendtx_url = confDict['SendTx-Url-Mainnet']

    buf = BytesIO()
    pyc = pycurl.Curl()

    pyc.setopt(pycurl.URL, sendtx_url)
    pyc.setopt(pycurl.CONNECTTIMEOUT, 50)
    pyc.setopt(pycurl.FAILONERROR, True)
    pyc.setopt(pycurl.USERAGENT, "Mozilla/5.0 (X11; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0")
    pyc.setopt(pycurl.HTTPHEADER, ['Accept: text/html', 'Accept-Charset: UTF-8'])
    # Set the WRITEFUNCTION to catch the output in buf
    pyc.setopt(pycurl.WRITEFUNCTION, buf.write)

    if (debug):
        print("Send Tx URL:", sendtx_url)

# DEPENDS ON THE SENDTX_URL_PROVIDER: (now blockr and webbtc, smartbit,
# TODO: could add more provider
    if sendtx_url.find("blockr") > 0:
        pyc.setopt(pycurl.POSTFIELDS, '{"hex":"%s"}' % (tx_hex))
        if (debug):
            print("Postdata:", '{"hex":"%s"}' % (tx_hex))
    elif sendtx_url.find("webbtc") > 0:
        pyc.setopt(pycurl.POSTFIELDS, '"wait=10&tx=%s"' % (tx_hex))
        if (debug):
            print("Postdata:", '"wait=10&tx=%s"' % (tx_hex))
    elif sendtx_url.find("smartbit") > 0:
        pyc.setopt(pycurl.POSTFIELDS, '{"hex":"%s"}' % (tx_hex))
        if (debug):
            print("Postdata:", '{"hex":"%s"}' % (tx_hex))
    else:
        msg = "No provider for sending transaction to the network"
        Err(msg)
# END

    pyc.setopt(pycurl.POST, 1)

    if (debug):
        pyc.setopt(pycurl.VERBOSE, True)

    try:
        pyc.perform()
    except pycurl.error as err:
        msg = "Error in sending transaction to the network" + str(err)
        Err(msg)

    response = buf.getvalue()
    buf.close()
    if (debug):
        print(response)

# DEPENDS ON THE SEND_URL_PROVIDER: (now blockr,webbtc,smartbit
    if sendtx_url.find("blockr") > 0:
        jsonobj = json.loads(response.decode())
        if "status" in jsonobj:
            status = jsonobj["status"]
        else:
            status = ""
        if "data" in jsonobj:    
            hash = jsonobj["data"]    # txid of the new transaction
        else:
            hash = ""
    elif sendtx_url.find("smartbit") > 0:
        jsonobj = json.loads(response.decode())
        if "success" in jsonobj:
            status = jsonobj["success"]
        else:
            status = ""
        if "txid" in jsonobj:    
            hash = jsonobj["txid"]    # txid of the new transaction
        else:
            hash = ""
    elif sendtx_url.find("webbtc") > 0:
        jsonobj = json.loads(response.decode())
        if "success" in jsonobj:
            status = jsonobj["success"]
        else:
            status = ""
        if "hash" in jsonobj:    
            hash = jsonobj["hash"]    # txid of the new transaction
# END

    if (status == 1 or status == "success"):
        msg = "Success in sending transaction to the network"
        Info(msg)
        exit()
    else:
        msg = "Failure in sending transaction to the network"
        Err(msg)


def decode_base58(bc, length):
    digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = 0
    for char in bc:
        if char in digits58:
            n = n * 58 + digits58.index(char)
        else:
            n = 0 
            pass
    return n.to_bytes(length, 'big')


# Next 3 functions are from Pybitcointools written by Vitalik Butern
# to prevent the "non-mandatory-script-verify-flag Error bug"
# The *pkcs11-tool* I am using still has this bug/error when using it for 
# bitcoins.  Pybitcointools solved it, see
# https://github.com/vbuterin/pybitcointools/issues/89


def get_code_string(base):
    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }
    if base in code_strings:
        return code_strings[base]
    else:
        Err("DER Enoding error")


def encode(val, base, minlen=0):
    # from pybitcointools, used by for der_encode
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00' if base == 256 else b'1' \
        if base == 58 else b'0'
    if (pad_size > 0):
        result_bytes = padding_element*pad_size + result_bytes

    result_string = ''.join([chr(y) for y in result_bytes])
    result = result_bytes if base == 256 else result_string

    return result


def der_encode_sig(r, s):
    # Takes (r, s) as ints and returns der encoded sig
    s = orderN-s if s > orderN // 2 else s    # BIP62 low s
    b1, b2 = encode(r, 256), encode(s, 256)
    if bytearray(b1)[0] & 0x80:  # if leading byte interpreted as negative
        b1 = b'\x00' + b1        # add null bytes
    if bytearray(b2)[0] & 0x80:
        b2 = b'\x00' + b2
    left  = b'\x02' + encode(len(b1), 256, 1) + b1
    right = b'\x02' + encode(len(b2), 256, 1) + b2
    sigbin = b'\x30' + encode(len(left+right), 256, 1) + left + right
    return sigbin


def checkbtcaddr(bc):
    # see http://rosettacode.org/wiki/Bitcoin/address_validation#Python
    bcbytes = decode_base58(bc, 25)
    return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]


def verdeel(a2p, mbtcval, amountfrom):
    #
    # distribute amount to pay (a2p +fee) over unspents (mbtcval) in mBTC
    # result returned in in amountfrom
    #

    global fee,paybackamount

    if (debug):
        print("verdeel:", a2p)

    sumutxo = 0.0  # sum of *all* unspents in mili BTC

    for txid in mbtcval:
        sumutxo += float(mbtcval[txid])
    if sumutxo < a2p + fee:
        Info("Not enough unspents available (amount-to-pay to high!)")
        return

    r2p = a2p  # rest-to-pay (without fee)

    totutxo = 0.0  #  total amount of *used* unspents
    numutxos = 0   #  total number of unspents

    for txid in mbtcval:
        amountfrom[txid] = 0

    for txid in mbtcval:
        if r2p <= (float(mbtcval[txid]) - fee):
            # enough in this unspent for the rest (incl. fee)
            amountfrom[txid] = r2p
            totutxo += float(mbtcval[txid])
            numutxos += 1
            r2p = 0
            # no more unspents needed
            break
        elif r2p < float(mbtcval[txid]):
            # enough in this unspent for the rest but *without* fee
            amountfrom[txid] = float(mbtcval[txid])  # take the whole unspent
            totutxo += float(mbtcval[txid])
            numutxos += 1
            r2p -= float(mbtcval[txid])
            if r2p <  0.0000:     # could happen...
                r2p = 0.0011    # the next unspent is needed for the fee, so keep a small rest-to-pay
                fee = fee - 0.0011
        else: 
            # take whole unspent, but its not enough 
            amountfrom[txid] = float(mbtcval[txid])  # take the whole unspent
            totutxo += float(mbtcval[txid])
            numutxos += 1
            r2p -= float(mbtcval[txid])
            
    # if its a complex transaction, make the fee somewhat higher
    if (numutxos > 6):
        fee = fee * 3 
    elif (numutxos > 3):
        fee = fee * 2 

    paybackamount = totutxo - a2p - fee

    if (debug):
        for txid in amountfrom:
            print(txid, "==>", amountfrom[txid])
        print("number of unspents:", numutxos)
        print("payback from last unspent:", paybackamount)

    # update GUI
    for txid in mbtcval:
        setamounts()

    return amountfrom


def setamounts():
    #
    # update values in GUI
    #

    global fee
    global homedir
    i = 0
    maxunspentlines = int(confDict['MaxUnspentLines'])
    for txid in mbtcval:
        amountfrom_entry[i].delete(0, END)
        if amountfrom[txid] < 0.00001:
            amountfrom_entry[i].insert(0, 'not used')
        elif amountfrom[txid] == 0.0011:
            amountfrom_entry[i].insert(0, 'needed for fee')
        else:
            amountfrom_entry[i].insert(0, str(amountfrom[txid]))
        i += 1
        if (i == maxunspentlines): break

    returntransaction_entry.delete(0, END)
    returntransaction_entry.insert(0, str(paybackamount))
    transactionfee_entry.delete(0, END)
    transactionfee_entry.insert(0, str(fee))
    now = datetime.datetime.now().strftime("%y-%m-%d-%H-%M-%S")
    txdir = confDict['BTCtransactionsDir']
    if txdir.find(homedir) == -1:
        txfilename.set(homedir + "/" + txdir + "/tx"+str(now)+".hex")
    else:
        txfilename.set(txdir + "/tx"+str(now)+".hex")


def buildtx(mbtcval, amountfrom, btcToAddress):
    #
    # create unsigned transaction with spended amount
    # to be called *after* verdeel
    #

    txin = []
    txout = []

    # spended amount mBTC from userinput to satoshi's in blockchain
    # mBTC    = 0.001 BTC      = 1/1000 BTC
    # satoshi = 0.00000001 BTC = 1/100.000 mBTC
    # COIN (from bitcoinlibrary = 1 BTC)  = 100.000.000 satoshis
    # COIN and factor are type int. Satoshi values are tpe int.
    # mBTC values are type float
    factor = int(COIN*0.001)  # 1 mBTC to satoshi

    # build list of tx-input structures (source-tx + empty scriptSig.)
    a2p = 0.0  # amount-to-pay in mBTC
    sumutxo = 0.0  # sum of unspents for returnvalue
    for txid in amountfrom:
        if amountfrom[txid] > 0.0:  # collect only the transactions with inputs
            # that are really used in verdeel() and compute the sum of unspents
            sumutxo += float(mbtcval[txid])
            a2p += amountfrom[txid]
            # create txin structure from source-tx + empty scriptSig
            # convert transaction id from little-endian (the blockchain
            # representation) to bytes with lx()
            srctx, voutstr = txid.split(":")
            srctx = lx(srctx)
            vout = int(voutstr[:-1])
            # txin structure: the source-tx + empty scriptSig.
            txin.append(CMutableTxIn(COutPoint(srctx, vout)))
            if (debug):
                print("input txid:", txid)
                print("amount:", float(mbtcval[txid]))

    # build txout, the first (vout 0) with amount to pay in satoshi
    topay_tx = int(a2p*factor)
    txout.append(CMutableTxOut(topay_tx, 
                 CBitcoinAddress(btcToAddress).to_scriptPubKey()))

    # second txout (vout 1) with return transaction (to my own bitcoinaddress)
    # paybackamount retam = sum of unspents - amount-to-pay - fee
    # only return to my own bitcoinaddress the restamount if > fee
    # (if not, it is added to the fee)
    retam = sumutxo - a2p - fee

    # fee is in mBTC
    # fee_tx should be feexx
    # _tx values are in Satoshis
    fee_tx = int(fee * factor)
    return_tx = int(retam*factor)

    feexx = sumutxo*factor - topay_tx - return_tx

    if (debug):
        print("topay_tx:", topay_tx, "Satoshi")
        print("return_tx:", return_tx, "Satoshi")
        print("fee_tx:", fee_tx, "Satoshi")
        print("feexx:", feexx, "Satoshi")
        print("sumutxo:", sumutxo, "mBtc")

    # should never happen:
    assert (feexx < fee_tx*1.01) and (feexx > fee_tx*0.99)
    maxfee = 4* float(confDict['Transactionfee'])
    assert (fee < maxfee) 

    if retam > fee:
        # only return to my own bitcoinaddress the restamount if its > fee
        # (if not, it is added to the fee)
        bitcoinAddress = confDict["Bitcoinaddress"]
        txout.append(CMutableTxOut(return_tx, 
                 CBitcoinAddress(bitcoinAddress).to_scriptPubKey()))

    # return the unsigned transaction
    return (txin, txout)


class PinDialog:
    def __init__(self, parent):
        top = self.top = Toplevel(parent)
        top.title("PIN Entry")
        top.lift()
        self.myLabel = Label(top, text='*** Please Enter your PIN: ***')
        self.myLabel.pack()
        self.myEntryBox = Entry(top, show="*")
        self.myEntryBox.bind("<Return>", self.sendpin)
        self.myEntryBox.pack()
        self.mySubmitButton = Button(top, text='Submit')
        self.mySubmitButton.bind("<Button-1>", self.sendpin)
        self.mySubmitButton.pack()
        self.myEntryBox.focus_set()
        self.pin = ""

    def sendpin(self, event):
        self.pin = self.myEntryBox.get()
        self.top.destroy()


def signtx(mbtcval, amountfrom, btcToAddress):
    #
    # check ToAddress,buildtx and sign tx
    #


    if not btcToAddress:
        # nothing to sign
        Info("Cannot sign: target-address is missing")
        return

    if not (checkbtcaddr(btcToAddress)):
        # nothing to sign
        Info('Cannot sign, error in bitcoin target-address')
        return

    txin, txout = buildtx(mbtcval, amountfrom, btcToAddress)

    if (debug):
        print("signtx:", txin, txout)

    sign(txin, txout)


def sign(txin, txout):
    # By signing, we prove that we own the amount from output and can spend it.

    pin = ''

    # create the *complete* unsigned transaction
    tx = CMutableTransaction(txin, txout)

    # create scriptPubKey for the transaction unlocking script
    # This is the standard bitcoin transaction "pay-to-pubkey-hash"
    bpubkey = confDict['Public-key']
    bpubkey.strip()
    bpubkey = x(bpubkey)  # convert hexstring to bytes
    txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(bpubkey),
                                OP_EQUALVERIFY, OP_CHECKSIG])

    ix = -1
    for trns in txin:
        ix += 1
        # Calculate the signature hash for transaction tx[ix], type SIGHASH_ALL:
        sighash = SignatureHash(txin_scriptPubKey, tx, ix, SIGHASH_ALL)
        if (debug):
            print("sighash-hex:", b2x(sighash))

        # writing a temporary file for the unsigned input
        ftmpin = tempfile.NamedTemporaryFile(delete=False)
        ftmpin.write(sighash)
        ftmpin.close()

        # temporary file for the output (signed sighash)
        ftmpout = tempfile.NamedTemporaryFile(delete=False)

        if (debug):
            print(ftmpin.name)
            print(ftmpout.name)

        # start pinentry dialog if pin unknown
        # parent-window is root
        if not pin:
            pinDialog = PinDialog(root)
            root.wait_window(pinDialog.top)
            pin = pinDialog.pin
            root.deiconify()
            root.lift()

        key_id = confDict["Key-ID"]
        # sign sighash, output r,s format
        command = ("pkcs11-tool --module " + p11module + 
                   " --mechanism ECDSA --pin " + pin + 
                   " --sign --signature-format rs --id " + key_id + 
                   "  --input-file " + ftmpin.name + " --output-file "
                   + ftmpout.name)
 
        if (debug):
            print(command)
        return_code = subprocess.call(command, shell=True)
        if (return_code != 0):
            Err("Error in signing with smartcard")

        # reading the file in  binary mode, signature is rs format
        fd = open(ftmpout.name, "rb")
        sigrs = fd.read()
        fd.close()
        if (debug):
            print("sigrs=",sigrs)
            print("sigrslen:",len(sigrs))

        # BIP 66
        # convert the byte sequence of 72 bytes into a tuple of 2 ints
        rbytes = sigrs[:32]
        sbytes = sigrs[32:]
        r = int.from_bytes(rbytes,byteorder='big')  # the ecdsa byteorder
        s = int.from_bytes(sbytes,byteorder='big')
        if (debug):
            print ("r=",r)
            print ("s=",s)

        sig = der_encode_sig(r,s)

        # delete temp files
        # if not (debug):
        os.unlink(ftmpin.name)
        os.unlink(ftmpout.name)

        if (debug):
            print("sig=", sig)

        # append the type of signature to the end (=SIGHASH_ALL)
        sig = sig + bytes([SIGHASH_ALL])

        #### Build the scriptSig of our transaction input and the public key
        #### put it  the txin at index ix
        txin[ix].scriptSig = CScript([sig, bpubkey])

    # Verify if the scriptSig satisfies the scriptPubkey (only first is enough)
    if (debug):
        print("txin[0].scriptSig=", txin[0].scriptSig)
        try:
            VerifyScript(txin[0].scriptSig, txin_scriptPubKey, tx, 0,
                         (SCRIPT_VERIFY_P2SH,))
            print("Scriptsig OK")
        except ValidationError:
            print("Error: bad scriptSig")

    if (debug):
        # Print the transaction to standard output in hex
        print(b2x(tx.serialize()))

    fout = open(txfilename.get(), "w")
    # writing the file in hex
    fout.write(b2x(tx.serialize()))
    fout.close()
    msg = "Signed transaction file written: "+txfilename.get()
    Info(msg)

###################  main  ########################

root = Tk()
# Ask configfile-id (~/.smartbtc/id.conf)
root.iconify()
confDialog = ConfDialog(root)
root.wait_window(confDialog.top)
id = confDialog.confid
root.deiconify()
if (debug):
    print("conf-id =", id)

# read the configfile
# set some globals from the config file
readConfig(id)
network = confDict['Network']
fee = float(confDict['Transactionfee'])
maxunspentlines = int(confDict['MaxUnspentLines'])

if (debug):
    print("Bitcoinaddress:", confDict['Bitcoinaddress'])
    print("Network=", network)
    print("Public-key:", confDict['Public-key'])
    print("Key-ID=", confDict['Key-ID'])
    print("fee:", fee)
    print("maxunspentlines:", maxunspentlines)


if (network == 'testnet'):
    provider_url = confDict['Provider-Url-Testnet']
    sendtx_url = confDict['SendTx-Url-Testnet']
if (network == 'mainnet'):
    provider_url = confDict['Provider-Url-Mainnet']
    sendtx_url = confDict['SendTx-Url-Mainnet']

if (debug):
    print("Provider-Url:", provider_url)
    print("Provider-SendTx-Url:", sendtx_url)

# get the unspends from provider

mbtcval, amountfrom = get_utxo(provider_url)
paybackamount = 0.0


######### GUI ##########

amount = StringVar()
amount.set('0')
toAddress = StringVar()
toAddress.set('')
returntransaction = StringVar()
returntransaction.set('0')
transactionfee = StringVar()
transactionfee.set('0')
# transaction filename (default)
txfilename = StringVar()
root.title("*** SMART=BITCOIN ***")
mainwin = ttk.Frame(root, padding="3 3 12 12")
r = 0
mainwin.grid(column=0, row=r, sticky=(N, W, E, S))
mainwin.columnconfigure(0, weight=1)
mainwin.rowconfigure(0, weight=1)

btcimgfile = homedir + "/" + ".smartbtc/" + "bitcoin64.png"
try:
    bitcoinpic = PhotoImage(file=btcimgfile)
    ttk.Label(mainwin, image=bitcoinpic).grid(column=3, row=r, sticky=(N, E))
except:
    if (debug):
        print("Could not load picturefile bitcoin64.png")
    pass

bitcoinAddress = confDict['Bitcoinaddress']
ttk.Label(mainwin, text="MY BITCOIN ADDRESS: ",
          font="TkHeadingFont").grid(column=1, row=r, sticky=(W, E))
ttk.Label(mainwin, text=bitcoinAddress,
          foreground='blue').grid(column=2, row=r, sticky=W)

r += 1  # next row
# list the Unspent Transaction Outputs (UTXO's)

r += 1
s = "======================"
ttk.Label(mainwin,
    text= s + " BITCOIN TRANSACTION (Values in mBTC) " + s,
    font="TkHeadingFont").grid(column=1, row=r, columnspan=2, sticky=(W, E))

r += 1
totalunspent = 0
i = 0   # first unspentline number
iu = 0  # unspent number
for txid in mbtcval:
    iu += 1 
    i += 1
    if i <= maxunspentlines:
        # only display if maxunspentlines for display is not reached
        ttk.Label(mainwin,
              text="Unspent (" + str(i) + "):").grid(column=1, row=r, sticky=E)
        ttk.Label(mainwin, text=txid).grid(column=2, row=r, sticky=(W, E))
        mbtcvalue = str(mbtcval[txid])
        pos = mbtcvalue.index('.')
        mbtcvalue = mbtcvalue[0:pos+3]
        rg = txid[-1]
        if (rg == 'g') :
        # display amount in red if not enough confimations
            ttk.Label(mainwin, text=mbtcvalue+" mBTC",
                  foreground = 'green').grid(column=3, row=r, sticky=E)
        elif (rg == 'r') :
            ttk.Label(mainwin, text=mbtcvalue+" mBTC",
                  foreground = 'red').grid(column=3, row=r, sticky=E)
        else:
            if (debug):
                print("No confirmationcolor red/green")
            ttk.Label(mainwin, text=mbtcvalue+" mBTC",
                  foreground = 'black').grid(column=3, row=r, sticky=E)
        r += 1
    totalunspent = totalunspent + float(mbtcval[txid])

totalunspstr = str(totalunspent)
ttk.Label(mainwin, text="*****Total Unspent in "+str(iu)+" unspents:").grid(column=1, 
          row=r, sticky=E)
ttk.Label(mainwin, text=totalunspstr, foreground="green").grid(column=2,
          row=r, sticky=(W, E))
ttk.Label(mainwin, text="mBTC").grid(column=3, row=r, sticky=E)
r += 1
ttk.Label(mainwin, text="Target Bitcoin Address:",font="Helvetica 10 bold").grid(column=1, row=r, sticky=E)
toAddress_entry = ttk.Entry(mainwin, width=34, textvariable=toAddress)
toAddress_entry.grid(column=2, row=r, sticky=(W, E))

r += 1
ttk.Label(mainwin, text="Amount to pay in mBTC:",font="Helvetica 10 bold").grid(column=1, row=r, sticky=E)
amount_entry = ttk.Entry(mainwin, width=20, textvariable=amount)
amount_entry.grid(column=2, row=r,  sticky=(W, E))
ttk.Label(mainwin, text="mBTC").grid(column=3, row=r, sticky=E)

r += 1
#  should be pressed after amount and to-address is given by the user
ttk.Button(mainwin, text="CREATE TRANSACTION",
           command=(lambda: verdeel(float(amount.get()), mbtcval,
           amountfrom))).grid(column=2, row=r, sticky=W)

# show the distribution from the amount-to-pay over the unspents
amountfrom_entry = []
i = 1  # spentline
for txid in amountfrom:
    if (i <= maxunspentlines):
        r += 1
        ttk.Label(mainwin,
            text="Amount from:"+str(i)+": ").grid(column=1, row=r, sticky=E)
        entry = ttk.Entry(mainwin, width=7)
        amountfrom_entry.append(entry)
        entry.delete(0, END)
        entry.insert(0, amountfrom[txid])
        entry.grid(column=2, row=r, sticky=(W, E))
        ttk.Label(mainwin, text="mBTC").grid(column=3, row=r, sticky=E)
        i += 1

r += 1
# Transaction Fee
ttk.Label(mainwin, text="Transaction Fee").grid(column=1, row=r, sticky=E)
transactionfee_entry = ttk.Entry(mainwin, width=7, textvariable=fee)
transactionfee_entry.grid(column=2, row=r, sticky=(W, E))
ttk.Label(mainwin, text="mBTC").grid(column=3, row=r, sticky=E)

r += 1
# Returntransaction, amount to pay back to myself
ttk.Label(mainwin, text="Returntransaction").grid(column=1, row=r, sticky=E)
returntransaction_entry = ttk.Entry(mainwin, width=7, 
                                    textvariable=str(paybackamount))
returntransaction_entry.grid(column=2, row=r, sticky=(W, E))
ttk.Label(mainwin, text="mBTC").grid(column=3, row=r, sticky=E)

r += 1
# sign transaction
ttk.Button(mainwin, text="SIGN TRANSACTION",
           command=(lambda: signtx(mbtcval, amountfrom,
           toAddress.get()))).grid(column=2, row=r, sticky=(W, E))
#for child in mainwin.winfo_children():
#    child.grid_configure(padx=5, pady=5)

r += 1
# push transaction
ttk.Button(mainwin, text="PUSH TRANSACTION TO NETWORK",
           command=(lambda: send_tx(network))).grid(column=2, row=r, sticky=(W, E))
#for child in mainwin.winfo_children():
#    child.grid_configure(padx=5, pady=5)

r += 1
ttk.Label(mainwin, text="transaction filename:").grid(column=1, row=r, sticky=E)
txfilename_entry = ttk.Entry(mainwin, width=20, textvariable=txfilename)
txfilename_entry.grid(column=2, row=r,  sticky=(W, E))

for child in mainwin.winfo_children():
    child.grid_configure(padx=3, pady=3)

root.mainloop()
