import sha3 from 'js-sha3';
import bs58 from 'bs58';
import JSSHA from 'jssha';
import bip39 from 'bip39';
import assert from 'assert';
import hdkey from 'hdkey';
import secp256k1 from 'secp256k1';
import { Buffer as Buffer$1 } from 'safe-buffer';
import { buildTransferTransaction, buildAccountUpdate, buildVote, buildFreezeBalance, buildUnfreezeBalance, buildAssetIssue, buildAssetParticipate } from '@tronscan/client/src/utils/transactionBuilder';
import { signTransaction } from '@tronscan/client/src/utils/crypto';

// credit - https://github.com/tronprotocol/node-wallet-api
const EC = require('elliptic').ec;

const prefixTestNet = 'a0';
const prefix = '41';

function computeAddress (pubBytes, isTestNet = false) {
  if (pubBytes.length === 65) {
    pubBytes = pubBytes.slice(1);
  }
  var hash = sha3.keccak256(pubBytes).toString();
  var addressHex = hash.substring(24);
  addressHex = (isTestNet ? prefixTestNet : prefix) + addressHex;
  var addressBytes = hexStr2byteArray(addressHex);
  return addressBytes
}

function getBase58CheckAddress (addressBytes) {
  var hash0 = SHA256(addressBytes);
  var hash1 = SHA256(hash0);
  var checkSum = hash1.slice(0, 4);
  checkSum = addressBytes.concat(checkSum);
  checkSum = Buffer.from(checkSum);
  var base58Check = bs58.encode(checkSum);
  return base58Check
}

function getPubKeyFromPriKey (priKeyBytes) {
  var ec = new EC('secp256k1');
  var key = ec.keyFromPrivate(priKeyBytes, 'bytes');
  var pubkey = key.getPublic();
  var x = pubkey.x;
  var y = pubkey.y;
  var xHex = x.toString('hex');
  while (xHex.length < 64) {
    xHex = '0' + xHex;
  }
  var yHex = y.toString('hex');
  while (yHex.length < 64) {
    yHex = '0' + yHex;
  }
  var pubkeyHex = '04' + xHex + yHex;
  var pubkeyBytes = hexStr2byteArray(pubkeyHex);
  return pubkeyBytes
}

function byte2hexStr (byte) {
  var hexByteMap = '0123456789ABCDEF';
  var str = '';
  str += hexByteMap.charAt(byte >> 4);
  str += hexByteMap.charAt(byte & 0x0f);
  return str
}

function byteArray2hexStr (byteArray) {
  let str = '';
  for (let i = 0; i < (byteArray.length); i++) {
    str += byte2hexStr(byteArray[i]);
  }
  return str
}

function isHexChar (c) {
  if ((c >= 'A' && c <= 'F') ||
      (c >= 'a' && c <= 'f') ||
      (c >= '0' && c <= '9')) {
    return 1
  }
  return 0
}

function hexChar2byte (c) {
  var d = 0;
  if (c >= 'A' && c <= 'F') {
    d = c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
  } else if (c >= 'a' && c <= 'f') {
    d = c.charCodeAt(0) - 'a'.charCodeAt(0) + 10;
  } else if (c >= '0' && c <= '9') {
    d = c.charCodeAt(0) - '0'.charCodeAt(0);
  }
  return d
}

function hexStr2byteArray (str) {
  var byteArray = [];
  var d = 0;
  var j = 0;
  var k = 0;

  for (let i = 0; i < str.length; i++) {
    var c = str.charAt(i);
    if (isHexChar(c)) {
      d <<= 4;
      d += hexChar2byte(c);
      j++;
      if ((j % 2) === 0) {
        byteArray[k++] = d;
        d = 0;
      }
    }
  }
  return byteArray
}

function longToByteArray (/* long */long) {
  // we want to represent the input as a 8-bytes array
  var byteArray = [0, 0, 0, 0, 0, 0, 0, 0];

  for (var index = 0; index < byteArray.length; index++) {
    var byte = long & 0xff;
    byteArray[ index ] = byte;
    long = (long - byte) / 256;
  }

  return byteArray
}

function SHA256 (msgBytes) {
  let shaObj = new JSSHA('SHA-256', 'HEX');
  let msgHex = byteArray2hexStr(msgBytes);
  shaObj.update(msgHex);
  let hashHex = shaObj.getHash('HEX');
  return hexStr2byteArray(hashHex)
}

function addRef (transaction, latestBlock) {
  let latestBlockHash = latestBlock.hash;
  let latestBlockNum = latestBlock.number;
  let numBytes = longToByteArray(latestBlockNum);
  numBytes.reverse();
  let hashBytes = hexStr2byteArray(latestBlockHash);
  let generateBlockId = [...numBytes.slice(0, 8), ...hashBytes.slice(8, hashBytes.length - 1)];
  let rawData = transaction.getRawData();
  rawData.setRefBlockHash(Uint8Array.from(generateBlockId.slice(8, 16)));
  rawData.setRefBlockBytes(Uint8Array.from(numBytes.slice(6, 8)));
  rawData.setExpiration(latestBlock.timestamp + (60 * 5 * 1000));
  transaction.setRawData(rawData);
  return transaction
}

class TronWallet {
  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  static fromMnemonic (mnemonic, isTestNet = false) {
    const seed = bip39.mnemonicToSeedHex(mnemonic);
    return new this({ seed, isTestNet })
  }

  static fromMasterSeed (seed, isTestNet = false) {
    return new this({ seed, isTestNet })
  }

  static fromExtendedKey (extendedKey, isTestNet = false) {
    return new this({ extendedKey, isTestNet })
  }

  static fromPrivateKey (privateKey, isTestNet = false) {
    return new this({ privateKey, isTestNet })
  }

  static fromTronPrivateKey (pk, isTestNet = false) {
    return new this({ privateKey: Buffer$1(pk, 'hex'), isTestNet })
  }

  constructor ({ seed, extendedKey, privateKey, isTestNet }) {
    if (seed) {
      this._seed = seed;
      this._node = hdkey.fromMasterSeed(Buffer$1(seed, 'hex'));
    } else if (extendedKey) {
      this._seed = null;
      this._node = hdkey.fromExtendedKey(extendedKey);
    } else {
      assert.equal(privateKey.length, 32, 'Private key must be 32 bytes.');
      assert(secp256k1.privateKeyVerify(privateKey), 'Invalid private key');
      this._seed = null;
      this._node = {
        _publicKey: secp256k1.publicKeyCreate(privateKey, true),
        _privateKey: privateKey
      };
    }
    this._isTestNet = isTestNet || false;
    this._init();
  }

  _init () {
    const priKey = this.getPrivateKey();
    let priKeyHex = priKey.toString('hex');
    while (priKeyHex.length < 64) {
      priKeyHex = '0' + priKeyHex;
    }
    this._priKeyBytes = hexStr2byteArray(priKeyHex);
  }

  derivePath (path) {
    assert(this._node.derive, 'can not derive when generate from private / public key');
    this._node = this._node.derive(path);
    return new TronWallet({ extendedKey: this._node.privateExtendedKey, isTestNet: this._isTestNet })
  }

  deriveChild (index) {
    assert(this._node.deriveChild, 'can not derive when generate from private / public key');
    this._node = this._node.deriveChild(index);
    return new TronWallet({ extendedKey: this._node.privateExtendedKey, isTestNet: this._isTestNet })
  }

  getPrivateExtendedKey () {
    assert(this._node.privateExtendedKey, 'can not get xpriv when generate from private / public key');
    return this._node.privateExtendedKey
  }

  getPublicExtendedKey () {
    assert(this._node.publicExtendedKey, 'can not get xpub when generate from private / public key');
    return this._node.publicExtendedKey
  }

  getPrivateKey () {
    assert(this._node._privateKey, 'can not get private when generate from public key');
    return this._node._privateKey
  }

  getTronPrivateKey () {
    return byteArray2hexStr(this._priKeyBytes)
  }

  getAddress () {
    const addressBytes = computeAddress(getPubKeyFromPriKey(this._priKeyBytes), this._isTestNet);
    return getBase58CheckAddress(addressBytes)
  }

  updateTransaction (tx, latestBlock) {
    const transactionWithRefs = addRef(tx, latestBlock);
    const signed = signTransaction(this.getTronPrivateKey(), transactionWithRefs);
    const shaObj = new JSSHA('SHA-256', 'HEX');
    shaObj.update(signed.hex);
    const txid = shaObj.getHash('HEX');
    return { txid, ...signed }
  }

  generateTransaction (to, amount, token = 'TRX', latestBlock) {
    const transaction = buildTransferTransaction(token, this.getAddress(), to, amount);
    return this.updateTransaction(transaction, latestBlock)
  }

  updateAccount (name, latestBlock) {
    const transaction = buildAccountUpdate(this.getAddress(), name);
    return this.updateTransaction(transaction, latestBlock)
  }

  freeze (amount, duration = 3, latestBlock) {
    const transaction = buildFreezeBalance(this.getAddress(), amount, duration);
    return this.updateTransaction(transaction, latestBlock)
  }

  unfreeze (latestBlock) {
    const transaction = buildUnfreezeBalance(this.getAddress());
    return this.updateTransaction(transaction, latestBlock)
  }

  vote (votes, latestBlock) {
    const transaction = buildVote(this.getAddress(), votes);
    return this.updateTransaction(transaction, latestBlock)
  }

  issueAssets (options, latestBlock) {
    const transaction = buildAssetIssue(options, latestBlock);
    return this.updateTransaction(transaction, latestBlock)
  }

  buyAssets (issuer, token, amount, latestBlock) {
    const transaction = buildAssetParticipate(this.getAddress(), issuer, token, amount);
    return this.updateTransaction(transaction, latestBlock)
  }
}

export default TronWallet;
