from io import BytesIO as _BytesIO
from copy import deepcopy
from abc import ABCMeta, abstractmethod
import bitcoin.core
from bitcoin.core.script import *
from binascii import unhexlify, hexlify
from base58 import b58encode, b58decode
from hashlib import sha256
from ecdsa import SigningKey
from ecdsa.util import sigencode_der_canonize, number_to_string
from urllib.request import urlopen, Request
from json import loads

import sys
_bchr = chr
_bord = ord

# if sys.version > '3':
long = int
def _bchr(x): return bytes([x])
def _bord(x): return x
# else:  # if Python 2
#     from cStringIO import StringIO as _BytesIO


# keys.py


def ecdsa_tx_sign(unsigned_tx, sk, hashflag=SIGHASH_ALL, deterministic=True):
    """ Performs and ECDSA sign over a given transaction using a given secret key.
    :param unsigned_tx: unsigned transaction that will be double-sha256 and signed.
    :type unsigned_tx: hex str
    :param sk: ECDSA private key that will sign the transaction.
    :type sk: SigningKey
    :param hashflag: hash type that will be used during the signature process and will identify the signature format.
    :type hashflag: int
    :param deterministic: Whether the signature is performed using a deterministic k or not. Set by default.
    :type deterministic: bool
    :return:
    """

    # Encode the hash type as a 4-byte hex value.
    if hashflag in [SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE]:
        hc = int2bytes(hashflag, 4)
    else:
        raise Exception("Wrong hash flag.")

    # ToDo: Deal with SIGHASH_ANYONECANPAY

    # sha-256 the unsigned transaction together with the hash type (little endian).
    h = sha256(unhexlify(unsigned_tx + change_endianness(hc))).digest()
    # Sign the transaction (using a sha256 digest, that will conclude with the double-sha256)
    # If deterministic is set, the signature will be performed deterministically choosing a k from the given transaction
    if deterministic:
        s = sk.sign_deterministic(
            h, hashfunc=sha256, sigencode=sigencode_der_canonize)
    # Otherwise, k will be chosen at random. Notice that this can lead to a private key disclosure if two different
    # messages are signed using the same k.
    else:
        s = sk.sign(h, hashfunc=sha256, sigencode=sigencode_der_canonize)

    # Finally, add the hashtype to the end of the signature as a 2-byte big endian hex value.
    return hexlify(s) + hc[-2:]


def serialize_pk(pk, compressed=True):
    """ Serializes a ecdsa.VerifyingKey (public key).

    :param compressed: Indicates if the serialized public key will be either compressed or uncompressed.
    :type compressed: bool
    :param pk: ECDSA VerifyingKey object (public key to be serialized).
    :type pk: ecdsa.VerifyingKey
    :return: serialized public key.
    :rtype: hex str
    """

    # Updated with code based on PR #54 from python-ecdsa until the PR gets merged:
    # https://github.com/warner/python-ecdsa/pull/54

    x_str = number_to_string(pk.pubkey.point.x(), pk.pubkey.order)

    if compressed:
        if pk.pubkey.point.y() & 1:
            prefix = '03'
        else:
            prefix = '02'

        s_key = prefix + hexlify(x_str)
    else:
        s_key = '04' + hexlify(pk.to_string())

    return s_key


# utils.py


def parse_script_type(t):
    """ Parses a script type obtained from a query to blockcyper's API.

    :param t: script type to be parsed.
    :type t: str
    :return: The parsed script type.
    :rtype: str
    """

    if t == 'pay-to-multi-pubkey-hash':
        r = "P2MS"
    elif t == 'pay-to-pubkey':
        r = "P2PK"
    elif t == 'pay-to-pubkey-hash':
        r = "P2PKH"
    elif t == 'pay-to-script-hash':
        r = "P2PSH"
    else:
        r = "unknown"

    return r


def get_prev_ScriptPubKey(tx_id, index, network='test'):
    """ Gets the ScriptPubKey of a given transaction id and its type, by querying blockcyer's API.

    :param tx_id: Transaction identifier to be queried.
    :type tx_id: hex str
    :param index: Index of the output from the transaction.
    :type index: int
    :param network: Network in which the transaction can be found (either mainnet or testnet).
    :type network: hex str
    :return: The corresponding ScriptPubKey and its type.
    :rtype hex str, str
    """

    if network in ['main', 'mainnet']:
        base_url = "https://api.blockcypher.com/v1/btc/main/txs/"
    elif network in ['test', 'testnet']:
        base_url = "https://api.blockcypher.com/v1/btc/test3/txs/"
    else:
        raise Exception("Bad network.")

    request = Request(base_url + tx_id)
    header = 'User-agent', 'Mozilla/5.0'
    request.add_header("User-agent", header)

    r = urlopen(request)

    data = loads(r.read())

    script = data.get('outputs')[index].get('script')
    t = data.get('outputs')[index].get('script_type')

    return script, parse_script_type(t)


def encode_varint(value):
    """ Encodes a given integer value to a varint. It only used the four varint representation cases used by bitcoin:
    1-byte, 2-byte, 4-byte or 8-byte integers.

    :param value: The integer value that will be encoded into varint.
    :type value: int
    :return: The varint representation of the given integer value.
    :rtype: str
    """

    # The value is checked in order to choose the size of its final representation.
    # 0xFD(253), 0xFE(254) and 0xFF(255) are special cases, since are the prefixes defined for 2-byte, 4-byte
    # and 8-byte long values respectively.
    if value < pow(2, 8) - 3:
        size = 1
        varint = int2bytes(value, size)  # No prefix
    else:
        if value < pow(2, 16):
            size = 2
            prefix = 253  # 0xFD
        elif value < pow(2, 32):
            size = 4
            prefix = 254  # 0xFE
        elif value < pow(2, 64):
            size = 8
            prefix = 255  # 0xFF
        else:
            raise Exception("Wrong input data size")
        varint = format(prefix, 'x') + \
            change_endianness(int2bytes(value, size))

    return varint


def decode_varint(varint):
    """ Decodes a varint to its standard integer representation.

    :param varint: The varint value that will be decoded.
    :type varint: str
    :return: The standard integer representation of the given varint.
    :rtype: int
    """

    # The length of the varint is check to know whether there is a prefix to be removed or not.
    if len(varint) > 2:
        decoded_varint = int(change_endianness(varint[2:]), 16)
    else:
        decoded_varint = int(varint, 16)

    return decoded_varint


def int2bytes(a, b):
    """ Converts a given integer value (a) its b-byte representation, in hex format.

    :param a: Value to be converted.
    :type a: int
    :param b: Byte size to be filled.
    :type b: int
    :return: The b-bytes representation of the given value (a) in hex format.
    :rtype: hex str
    """

    m = pow(2, 8*b) - 1
    if a > m:
        raise Exception(str(a) + " is too big to be represented with " +
                        str(b) + " bytes. Maximum value is " + str(m) + ".")

    return ('%0' + str(2 * b) + 'x') % a


def parse_varint(tx):
    """ Parses a given transaction for extracting an encoded varint element.

    :param tx: Transaction where the element will be extracted.
    :type tx: TX
    :return: The b-bytes representation of the given value (a) in hex format.
    :rtype: hex str
    """

    # First of all, the offset of the hex transaction if moved to the proper position (i.e where the varint should be
    #  located) and the length and format of the data to be analyzed is checked.
    data = tx.hex[tx.offset:]
    assert (len(data) > 0)
    size = int(data[:2], 16)
    assert (size <= 255)

    # Then, the integer is encoded as a varint using the proper prefix, if needed.
    if size <= 252:  # No prefix
        storage_length = 1
    elif size == 253:  # 0xFD
        storage_length = 3
    elif size == 254:  # 0xFE
        storage_length = 5
    elif size == 255:  # 0xFF
        storage_length = 9
    else:
        raise Exception("Wrong input data size")

    # Finally, the storage length is used to extract the proper number of bytes from the transaction hex and the
    # transaction offset is updated.
    varint = data[:storage_length * 2]
    tx.offset += storage_length * 2

    return varint


def parse_element(tx, size):
    """ Parses a given transaction to extract an element of a given size.

    :param tx: Transaction where the element will be extracted.
    :type tx: TX
    :param size: Size of the parameter to be extracted.
    :type size: int
    :return: The extracted element.
    :rtype: hex str
    """

    element = tx.hex[tx.offset:tx.offset + size * 2]
    tx.offset += size * 2
    return element


def change_endianness(x):
    """ Changes the endianness (from BE to LE and vice versa) of a given value.

    :param x: Given value which endianness will be changed.
    :type x: hex str
    :return: The opposite endianness representation of the given value.
    :rtype: hex str
    """

    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = hexlify(unhexlify(x)[::-1]).decode()
    # y = x.encode()  # .decode('hex')
    # z = hexlify(y[::-1]).decode()
    return y


def check_signature(signature):
    """ Checks if a given string is a signature (or at least if it is formatted as if it is).

    :param signature: Signature to be checked.
    :type signature: hex str
    :return: True if the signatures matches the format, raise exception otherwise.
    :rtype: bool
    """

    l = (len(signature[4:]) - 2) / 2

    if signature[:2] != "30":
        raise Exception("Wrong signature format.")
    elif int(signature[2:4], 16) != l:
        raise Exception("Wrong signature length " + str(l))
    else:
        return True


def check_script(script):
    """ Checks if a given string is a script (hash160) (or at least if it is formatted as if it is).

    :param script: Script to be checked.
    :type script: hex str
    :return: True if the signatures matches the format, raise exception otherwise.
    :rtype: bool
    """

    if not isinstance(script, str):
        raise Exception("Wrong script format.")
    elif len(script)/2 != 20:
        raise Exception("Wrong signature length " + str(len(script)/2))
    else:
        return True


def check_address(btc_addr, network='test'):
    """ Checks if a given string is a Bitcoin address for a given network (or at least if it is formatted as if it is).

    :param btc_addr: Bitcoin address to be checked.
    :rtype: hex str
    :param network: Network to be checked (either mainnet or testnet).
    :type network: hex str
    :return: True if the Bitcoin address matches the format, raise exception otherwise.
    """

    if network in ['test', "testnet"] and btc_addr[0] not in ['m', 'n']:
        raise Exception("Wrong testnet address format.")
    elif network in ['main', 'mainnet'] and btc_addr[0] != '1':
        raise Exception("Wrong mainnet address format.")
    elif network not in ['test', 'testnet', 'main', 'mainnet']:
        raise Exception("Network must be test/testnet or main/mainnet")
    elif len(btc_addr) not in range(26, 35+1):
        raise Exception(
            "Wrong address format, Bitcoin addresses should be 27-35 hex char long.")
    else:
        return True


def check_public_key(pk):
    """ Checks if a given string is a public (or at least if it is formatted as if it is).

    :param pk: ECDSA public key to be checked.
    :type pk: hex str
    :return: True if the key matches the format, raise exception otherwise.
    :rtype: bool
    """

    prefix = pk[0:2]
    l = len(pk)

    if prefix not in ["02", "03", "04"]:
        raise Exception("Wrong public key format.")
    if prefix == "04" and l != 130:
        raise Exception(
            "Wrong length for an uncompressed public key: " + str(l))
    elif prefix in ["02", "03"] and l != 66:
        raise Exception("Wrong length for a compressed public key: " + str(l))
    else:
        return True


def is_public_key(pk):
    """ Encapsulates check_public_key function as a True/False option.

    :param pk: ECDSA public key to be checked.
    :type pk: hex str
    :return: True if pk is a public key, false otherwise.
    """

    try:
        return check_public_key(pk)
    except:
        return False


def is_btc_addr(btc_addr, network='test'):
    """ Encapsulates check_address function as a True/False option.

    :param btc_addr: Bitcoin address to be checked.
    :type btc_addr: hex str
    :param network: The network to be checked (either mainnet or testnet).
    :type network: str
    :return: True if btc_addr is a public key, false otherwise.
    """

    try:
        return check_address(btc_addr, network)
    except:
        return False


def is_script(script):
    """ Encapsulates check_script function as a True/False option.

    :param script: Script to be checked.
    :type script: hex str
    :return: True if script is a script, false otherwise.
    """

    try:
        return check_script(script)
    except:
        return False


# wallet.py
def btc_addr_to_hash_160(btc_addr):
    """ Calculates the RIPEMD-160 hash from a given Bitcoin address

    :param btc_addr: Bitcoin address.
    :type btc_addr: str
    :return: The corresponding RIPEMD-160 hash.
    :rtype: hex str
    """

    # Base 58 decode the Bitcoin address.
    decoded_addr = b58decode(btc_addr)
    # Covert the address from bytes to hex.
    decoded_addr_hex = hexlify(decoded_addr)
    # Obtain the RIPEMD-160 hash by removing the first and four last bytes of the decoded address, corresponding to
    # the network version and the checksum of the address.
    h160 = decoded_addr_hex[2:-8]

    return h160

# Classes


class Script:
    """ Defines the class Script which includes two subclasses, InputScript and OutputScript. Every script type have two
    custom 'constructors' (from_hex and from_human), and four templates for the most common standard script types
    (P2PK, P2PKH, P2MS and P2PSH).
    """

    __metaclass__ = ABCMeta

    def __init__(self):
        self.content = ""
        self.type = "unknown"

    @classmethod
    def from_hex(cls, hex_script):
        """ Builds a script from a serialized one (it's hexadecimal representation).

        :param hex_script: Serialized script.
        :type hex_script: hex str
        :return: Script object with the serialized script as it's content.
        :rtype Script
        """
        script = cls()
        script.content = hex_script

        return script

    @classmethod
    def from_human(cls, data):
        """ Builds a script from a human way of writing them, using the Bitcoin Scripting language terminology.

        e.g: OP_DUP OP_HASH160 <hash_160> OP_EQUALVERIFY OP_CHECKSIG

        Every piece of data included in the script (everything except for op_codes) must be escaped between '<' '>'.

        :param data: Human readable Bitcoin Script (with data escaped between '<' '>')
        :type data: hex str
        :return: Script object with the serialization from the input script as it's content.
        :rtype. hex Script
        """

        script = cls()
        script.content = script.serialize(data)

        return script

    @staticmethod
    def deserialize(script):
        """ Deserializes a serialized script (goes from hex to human).

        e.g: deserialize('76a914b34bbaac4e9606c9a8a6a720acaf3018c9bc77c988ac') =   OP_DUP OP_HASH160 
            <b34bbaac4e9606c9a8a6a720acaf3018c9bc77c9> OP_EQUALVERIFY OP_CHECKSIG

        :param script: Serialized script to be deserialized.
        :type script: hex str
        :return: Deserialized script
        :rtype: hex str
        """

        start = "CScript(["
        end = "])"

        ps = CScript(unhexlify(script)).__repr__()
        ps = ps[ps.index(start) + len(start): ps.index(end)].split(", ")

        for i in range(len(ps)):
            if ps[i].startswith('x('):
                ps[i] = ps[i][3:-2]
                ps[i] = '<' + ps[i] + '>'

        return " ".join(ps)

    @staticmethod
    def serialize(data):
        """ Serializes a scrip from a deserialized one (human readable) (goes from human to hex)
        :param data: Human readable script.
        :type data: hex str
        :return: Serialized script.
        :rtype: hex str
        """

        hex_string = ""
        for e in data.split(" "):
            if e[0] == "<" and e[-1] == ">":
                hex_string += hexlify(
                    CScriptOp.encode_op_pushdata(unhexlify(e[1:-1])))
            elif eval(e) in OPCODE_NAMES:
                hex_string += format(eval(e), '02x')
            else:
                raise Exception

        return hex_string

    def get_element(self, i):
        """
        Returns the ith element from the script. If -1 is passed as index, the last element is returned.
        :param i: The index of the selected element.
        :type i: int
        :return: The ith elements of the script.
        :rtype: str
        """

        return Script.deserialize(self.content).split()[i]

    @abstractmethod
    def P2PK(self):
        pass

    @abstractmethod
    def P2PKH(self):
        pass

    @abstractmethod
    def P2MS(self):
        pass

    @abstractmethod
    def P2SH(self):
        pass


class InputScript(Script):
    """ Defines an InputScript (ScriptSig) class that inherits from script.
    """

    @classmethod
    def P2PK(cls, signature):
        """ Pay-to-PubKey template 'constructor'. Builds a P2PK InputScript from a given signature.

        :param signature: Transaction signature.
        :type signature: hex str
        :return: A P2PK sScriptSig built using the given signature.
        :rtype: hex str
        """

        script = cls()
        if check_signature(signature):
            script.type = "P2PK"
            script.content = script.serialize("<" + signature + ">")

        return script

    @classmethod
    def P2PKH(cls, signature, pk):
        """ Pay-to-PubKeyHash template 'constructor'. Builds a P2PKH InputScript from a given signature and a
        public key.

        :param signature: Transaction signature.
        :type signature: hex str
        :param pk: Public key from the same key pair of the private key used to perform the signature.
        :type pk: hex str
        :return: A P2PKH ScriptSig built using the given signature and the public key.
        :rtype: hex str
        """

        script = cls()
        if check_signature(signature) and check_public_key(pk):
            script.type = "P2PKH"
            script.content = script.serialize(
                "<" + signature + "> <" + pk + ">")

        return script

    @classmethod
    def P2MS(cls, sigs):
        """ Pay-to-Multisig template 'constructor'. Builds a P2MS InputScript from a given list of signatures.

        :param sigs: List of transaction signatures.
        :type sigs: list
        :return: A P2MS ScriptSig built using the given signatures list.
        :rtype: hex str
        """

        script = cls()
        s = "OP_0"
        for sig in sigs:
            if check_signature(sig):
                s += " <" + sig + ">"

        script.type = "P2MS"
        script.content = script.serialize(s)

        return script

    @classmethod
    def P2SH(cls, data, s):
        """ Pay-to-ScriptHash template 'constructor'. Builds a P2SH InputScript from a given script.

        :param data: Input data that will be evaluated with the script content once its hash had been checked against
        the hash provided by the OutputScript.
        :type data: list
        :param s: Human readable script that hashes to the UTXO script hash that the transaction tries to redeem.
        :type s: hex str
        :return: A P2SH ScriptSig (RedeemScript) built using the given script.
        :rtype: hex str
        """

        script = cls()
        for d in data:
            if isinstance(d, str) and d.startswith("OP"):
                # If an OP_CODE is passed as data (such as OP_0 in multisig transactions), the element is encoded as is.
                script.content += d + " "
            else:
                # Otherwise, the element is encoded as data.
                script.content += "<" + str(d) + "> "
        script.type = "P2SH"
        script.content = script.serialize(
            script.content + "<" + script.serialize(s) + ">")

        return script


class OutputScript(Script):
    """ Defines an OutputScript (ScriptPubKey) class that inherits from script.
    """

    @classmethod
    def P2PK(cls, pk):
        """ Pay-to-PubKey template 'constructor'. Builds a P2PK OutputScript from a given public key.

        :param pk: Public key to which the transaction output will be locked to.
        :type pk: hex str
        :return: A P2PK ScriptPubKey built using the given public key.
        :rtype: hex str
        """

        script = cls()
        if check_public_key(pk):
            script.type = "P2PK"
            script.content = script.serialize("<"+pk+"> OP_CHECKSIG")

        return script

    @classmethod
    def P2PKH(cls, data, network='test', hash160=False):
        """ Pay-to-PubKeyHash template 'constructor'. Builds a P2PKH OutputScript from a given Bitcoin address / hash160
        of a Bitcoin address and network.

        :param data: Bitcoin address or hash160 of a Bitcoin address to which the transaction output will be locked to.
        :type data: hex str
        :param network: Bitcoin network (either mainnet or testnet)
        :type network: hex str
        :param hash160: If set, the given data is the hash160 of a Bitcoin address, otherwise, it is a Bitcoin address.
        :type hash160: bool
        :return: A P2PKH ScriptPubKey built using the given bitcoin address and network.
        :rtype: hex str
        """

        if network in ['testnet', 'test', 'mainnet', 'main']:
            script = cls()
            if not hash160 and check_address(data, network):
                h160 = btc_addr_to_hash_160(data)
            else:
                h160 = data
            script.type = "P2PKH"
            script.content = script.serialize(
                "OP_DUP OP_HASH160 <" + h160 + "> OP_EQUALVERIFY OP_CHECKSIG")

            return script
        else:
            raise Exception("Unknown Bitcoin network.")

    @classmethod
    def P2MS(cls, m, n, pks):
        """ Pay-to-Multisig template 'constructor'. Builds a P2MS OutputScript from a given list of public keys, the total
        number of keys and a threshold.

        :param m: Threshold, minimum amount of signatures needed to redeem from the output.
        :type m: int
        :param n: Total number of provided public keys.
        :type n: int
        :param pks: List of n public keys from which the m-of-n multisig output will be created.
        :type pks: list
        :return: A m-of-n Pay-to-Multisig script created using the provided public keys.
        :rtype: hex str
        """

        script = cls()
        if n != len(pks):
            raise Exception("The provided number of keys does not match the expected one: " + str(len(pks)) +
                            "!=" + str(n))
        elif m not in range(1, 15) or n not in range(1, 15):
            raise Exception("Multisig transactions must be 15-15 at max")
        else:
            s = "OP_" + str(m)
            for pk in pks:
                if check_public_key(pk):
                    s += " <" + pk + ">"

        script.type = "P2MS"
        script.content = script.serialize(
            s + " OP_" + str(n) + " OP_CHECKMULTISIG")

        return script

    @classmethod
    def P2SH(cls, script_hash):
        """ Pay-to-ScriptHash template 'constructor'. Builds a P2SH OutputScript from a given script hash.

        :param script_hash: Script hash to which the output will be locked to.
        :type script_hash: hex str
        :return: A P2SH ScriptPubKey built using the given script hash.
        :rtype: hex str
        """

        script = cls()
        l = len(script_hash)
        if l != 40:
            raise Exception("Wrong RIPEMD-160 hash length: " + str(l))
        else:
            script.type = "P2SH"
            script.content = script.serialize(
                "OP_HASH160 <" + script_hash + "> OP_EQUAL")

        return script


class TX:
    """ Defines a class TX (transaction) that holds all the modifiable fields of a Bitcoin transaction, such as
    version, number of inputs, reference to previous transactions, input and output scripts, value, etc.
    """

    def __init__(self):
        self.version = None
        self.inputs = None
        self.outputs = None
        self.nLockTime = None
        self.prev_tx_id = []
        self.prev_out_index = []
        self.scriptSig = []
        self.scriptSig_len = []
        self.nSequence = []
        self.value = []
        self.scriptPubKey = []
        self.scriptPubKey_len = []

        self.offset = 0
        self.hex = ""

    @classmethod
    def build_from_hex(cls, hex_tx):
        """
        Alias of deserialize class method.

        :param hex_tx: Hexadecimal serialized transaction.
        :type hex_tx: hex str
        :return: The transaction build using the provided hex serialized transaction.
        :rtype: TX
        """

        return cls.deserialize(hex_tx)

    @classmethod
    def build_from_scripts(cls, prev_tx_id, prev_out_index, value, scriptSig, scriptPubKey, fees=None):
        """ Builds a transaction from already built Input and Output scripts. This builder should be used when building
        custom transaction (Non-standard).

        :param prev_tx_id: Previous transaction id.
        :type prev_tx_id: either str or list of str
        :param prev_out_index: Previous output index. Together with prev_tx_id represent the UTXOs the current
        transaction is aiming to redeem.
        :type prev_out_index: either str or list of str
        :param value: Value in Satoshis to be spent.
        :type value: either int or list of int
        :param scriptSig: Input script containing the restrictions that will lock the transaction.
        :type scriptSig: either InputScript or list of InputScript
        :param scriptPubKey: Output script containing the redeem fulfilment conditions.
        :type scriptPubKey: either OutputScript or list of OutputScript
        :param fees: Fees that will be applied to the transaction. If set, fees will be subtracted from the last output.
        :type fees: int
        :return: The transaction build using the provided scripts.
        :rtype: TX
        """

        tx = cls()

        # Normalize all parameters
        if isinstance(prev_tx_id, str):
            prev_tx_id = [prev_tx_id]
        if isinstance(prev_out_index, int):
            prev_out_index = [prev_out_index]
        if isinstance(value, int):
            value = [value]
        if isinstance(scriptSig, InputScript):
            scriptSig = [scriptSig]
        if isinstance(scriptPubKey, OutputScript):
            scriptPubKey = [scriptPubKey]

        if len(prev_tx_id) is not len(prev_out_index) or len(prev_tx_id) is not len(scriptSig):
            raise Exception(
                "The number ofs UTXOs to spend must match with the number os ScriptSigs to set.")
        elif len(scriptSig) == 0 or len(scriptPubKey) == 0:
            raise Exception("Scripts can't be empty")
        else:
            tx.version = 1

            # INPUTS
            tx.inputs = len(prev_tx_id)
            tx.prev_tx_id = prev_tx_id
            tx.prev_out_index = prev_out_index

            for i in range(tx.inputs):
                # ScriptSig
                tx.scriptSig_len.append(len(scriptSig[i].content) / 2)
                tx.scriptSig.append(scriptSig[i])

                tx.nSequence.append(pow(2, 32) - 1)  # ffffffff

            # OUTPUTS
            tx.outputs = len(scriptPubKey)

            for i in range(tx.outputs):
                tx.value.append(value[i])
                # ScriptPubKey
                tx.scriptPubKey_len.append(len(scriptPubKey[i].content) / 2)
                tx.scriptPubKey.append(scriptPubKey[i])  # Output script.

            # If fees have been set, subtract them from the final value. Otherwise, assume they have been already
            # subtracted when specifying the amounts.
            if fees:
                tx.value[-1] -= fees

            tx.nLockTime = 0

            tx.hex = tx.serialize()

        return tx

    @classmethod
    def build_from_io(cls, prev_tx_id, prev_out_index, value, outputs, fees=None, network='test'):
        """ Builds a transaction from a collection of inputs and outputs, such as previous transactions references and
        output references (either public keys, Bitcoin addresses, list of public keys (for multisig transactions), etc).
        This builder leaves the transaction ready to sign, so its the one to be used in most cases
        (Standard transactions).

        outputs format:

        P2PKH -> Bitcoin address, or list of Bitcoin addresses.
        e.g: output = btc_addr or output = [btc_addr0, btc_addr1, ...]

        P2PK -> Serialized Public key, or list of serialized pubic keys. (use keys.serialize_pk)
        e.g: output = pk or output = [pk0, pk1, ...]

        P2MS -> List of int (m) and public keys, or list of lists of int (m_i) and public keys. m represent the m-of-n
        number of public keys needed to redeem the transaction.
        e.g: output = [n, pk0, pk1, ...] or output = [[n_0, pk0_0, pk0_1, ...], [n_1, pk1_0, pk1_1, ...], ...]

        P2SH -> script hash (hash160 str hex) or list of hash 160s.
        e.g: output = da1745e9b549bd0bfa1a569971c77eba30cd5a4b or output = [da1745e9b549bd0bfa1a569971c77eba30cd5a4b,
        ...]

        :param prev_tx_id: Previous transaction id.
        :type prev_tx_id: either str or list of str
        :param prev_out_index: Previous output index. Together with prev_tx_id represent the UTXOs the current
        transaction is aiming to redeem.
        :type prev_out_index: either str or list of str
        :param value: Value in Satoshis to be spent.
        :type value: either int or list of int
        :param outputs: Information to build the output of the transaction.
        :type outputs: See above outputs format.
        :param fees: Fees that will be applied to the transaction. If set, fees will be subtracted from the last output.
        :type fees: int
        :param network: Network into which the transaction will be published (either mainnet or testnet).
        :type network: str
        :return: Transaction build with the input and output provided data.
        :rtype: TX
        """

        ins = []
        outs = []

        # Normalize all parameters
        if isinstance(prev_tx_id, str):
            prev_tx_id = [prev_tx_id]
        if isinstance(prev_out_index, int):
            prev_out_index = [prev_out_index]
        if isinstance(value, int):
            value = [value]
        if isinstance(outputs, str) or (isinstance(outputs, list) and isinstance(outputs[0], int)):
            outputs = [outputs]

        # If fees have been set, subtract them from the final value. Otherwise, assume they have been already
        # subtracted when specifying the amounts.
        if fees:
            value[-1] -= fees

        if len(prev_tx_id) != len(prev_out_index):
            raise Exception("Previous transaction id and index number of elements must match. " + str(len(prev_tx_id))
                            + "!= " + str(len(prev_out_index)))
        elif len(value) != len(outputs):
            raise Exception(
                "Each output must have set a Satoshi amount. Use 0 if no value is going to be transferred.")

        for o in outputs:
            # Multisig outputs are passes ad an integer m representing the m-of-n transaction, amb m public keys.
            if isinstance(o, list) and o[0] in range(1, 15):
                pks = [is_public_key(pk) for pk in o[1:]]
                if all(pks):
                    oscript = OutputScript.P2MS(o[0], len(o) - 1, o[1:])
                else:
                    raise Exception("Bad output")
            elif is_public_key(o):
                oscript = OutputScript.P2PK(o)
            elif is_btc_addr(o, network):
                oscript = OutputScript.P2PKH(o)
            elif is_script(o):
                oscript = OutputScript.P2SH(o)
            else:
                raise Exception("Bad output")

            outs.append(deepcopy(oscript))

        for _ in range(len(prev_tx_id)):
            # Temporarily set IS content to 0, since data will be signed afterwards.
            iscript = InputScript()
            ins.append(iscript)

        # Once all inputs and outputs has been formatted as scripts, we could construct the transaction with the proper
        # builder.
        tx = cls.build_from_scripts(
            prev_tx_id, prev_out_index, value, ins, outs)

        return tx

    @classmethod
    def deserialize(cls, hex_tx):
        """ Builds a transaction object from the hexadecimal serialization format of a transaction that
        could be obtained, for example, from a blockexplorer.

        :param hex_tx: Hexadecimal serialized transaction.
        :type hex_tx: hex str
        :return: The transaction build using the provided hex serialized transaction.
        :rtype: TX
        """

        tx = cls()
        tx.hex = hex_tx

        tx.version = int(change_endianness(parse_element(tx, 4)), 16)

        # INPUTS
        tx.inputs = int(parse_varint(tx), 16)

        for i in range(tx.inputs):
            tx.prev_tx_id.append(change_endianness(parse_element(tx, 32)))
            tx.prev_out_index.append(
                int(change_endianness(parse_element(tx, 4)), 16))
            # ScriptSig
            tx.scriptSig_len.append(int(parse_varint(tx), 16))
            tx.scriptSig.append(InputScript.from_hex(
                parse_element(tx, tx.scriptSig_len[i])))
            tx.nSequence.append(int(parse_element(tx, 4), 16))

        # OUTPUTS
        tx.outputs = int(parse_varint(tx), 16)

        for i in range(tx.outputs):
            tx.value.append(int(change_endianness(parse_element(tx, 8)), 16))
            # ScriptPubKey
            tx.scriptPubKey_len.append(int(parse_varint(tx), 16))
            tx.scriptPubKey.append(OutputScript.from_hex(
                parse_element(tx, tx.scriptPubKey_len[i])))

        tx.nLockTime = int(parse_element(tx, 4), 16)

        if tx.offset != len(tx.hex):
            raise Exception("There is some error in the serialized transaction passed as input. Transaction can't"
                            " be built")
        else:
            tx.offset = 0

        return tx

    def serialize(self, rtype=hex):
        """ Serialize all the transaction fields arranged in the proper order, resulting in a hexadecimal string
        ready to be broadcast to the network.

        :param self: self
        :type self: TX
        :param rtype: Whether the serialized transaction is returned as a hex str or a byte array.
        :type rtype: hex or bool
        :return: Serialized transaction representation (hexadecimal or bin depending on rtype parameter).
        :rtype: hex str / bin
        """

        if rtype not in [hex, bin]:
            raise Exception(
                "Invalid return type (rtype). It should be either hex or bin.")
        # 4-byte version number (LE).
        serialized_tx = change_endianness(int2bytes(self.version, 4))

        # INPUTS
        serialized_tx += encode_varint(self.inputs)  # Varint number of inputs.

        for i in range(self.inputs):
            # 32-byte hash of the previous transaction (LE).
            serialized_tx += change_endianness(self.prev_tx_id[i])
            # 4-byte output index (LE)
            serialized_tx += change_endianness(
                int2bytes(self.prev_out_index[i], 4))
            # Varint input script length.
            serialized_tx += encode_varint(len(self.scriptSig[i].content) / 2)
            # ScriptSig
            serialized_tx += self.scriptSig[i].content  # Input script.
            # 4-byte sequence number.
            serialized_tx += int2bytes(self.nSequence[i], 4)

        # OUTPUTS
        # Varint number of outputs.
        serialized_tx += encode_varint(self.outputs)

        if self.outputs != 0:
            for i in range(self.outputs):
                # 8-byte field Satoshi value (LE)
                serialized_tx += change_endianness(int2bytes(self.value[i], 8))
                # ScriptPubKey
                # Varint Output script length.
                serialized_tx += encode_varint(
                    len(self.scriptPubKey[i].content) / 2)
                serialized_tx += self.scriptPubKey[i].content  # Output script.

        serialized_tx += int2bytes(self.nLockTime, 4)  # 4-byte lock time field

        # If return type has been set to binary, the serialized transaction is converted.
        if rtype is bin:
            serialized_tx = unhexlify(serialized_tx)

        return serialized_tx

    def get_txid(self, rtype=hex, endianness="LE"):
        """ Computes the transaction id (i.e: transaction hash for non-segwit txs).
        :param rtype: Defines the type of return, either hex str or bytes.
        :type rtype: str or bin
        :param endianness: Whether the id is returned in BE (Big endian) or LE (Little Endian) (default one)
        :type endianness: str
        :return: The hash of the transaction (i.e: transaction id)
        :rtype: hex str or bin, depending on rtype parameter.
        """

        if rtype not in [hex, bin]:
            raise Exception(
                "Invalid return type (rtype). It should be either hex or bin.")
        if endianness not in ["BE", "LE"]:
            raise Exception(
                "Invalid endianness type. It should be either BE or LE.")

        if rtype is hex:
            tx_id = hexlify(
                sha256(sha256(self.serialize(rtype=bin)).digest()).digest())
            if endianness == "BE":
                tx_id = change_endianness(tx_id)
        else:
            tx_id = sha256(sha256(self.serialize(rtype=bin)).digest()).digest()
            if endianness == "BE":
                tx_id = unhexlify(change_endianness(hexlify(tx_id)))

        return tx_id

    def sign(self, sk, index, hashflag=SIGHASH_ALL, compressed=True, orphan=False, deterministic=True, network='test'):
        """ Signs a transaction using the provided private key(s), index(es) and hash type. If more than one key and index
        is provides, key i will sign the ith input of the transaction.

        :param sk: Private key(s) used to sign the ith transaction input (defined by index).
        :type sk: SigningKey or list of SigningKey.
        :param index: Index(es) to be signed by the provided key(s).
        :type index: int or list of int
        :param hashflag: Hash type to be used. It will define what signature format will the unsigned transaction have.
        :type hashflag: int
        :param compressed: Indicates if the public key that goes along with the signature will be compressed or not.
        :type compressed: bool
        :param orphan: Whether the inputs to be signed are orphan or not. Orphan inputs are those who are trying to
        redeem from a utxo that has not been included in the blockchain or has not been seen by other nodes.
        Orphan inputs must provide a dict with the index of the input and an OutputScript that matches the utxo to be
        redeemed.
            e.g:
              orphan_input = dict({0: OutputScript.P2PKH(btc_addr))
        :type orphan:  dict(index, InputScript)
        :param deterministic: Whether the signature is performed using a deterministic k or not. Set by default.
        :type deterministic: bool
        :param network: Network from which the previous ScripPubKey will be queried (either main or test).
        :type network: str
        :return: Transaction signature.
        :rtype: str
        """

        # Normalize all parameters
        if isinstance(sk, list) and isinstance(index, int):
            # In case a list for multisig is received as only input.
            sk = [sk]
        if isinstance(sk, SigningKey):
            sk = [sk]
        if isinstance(index, int):
            index = [index]

        for i in range(len(sk)):

            # If the input to be signed is orphan, the OutputScript of the UTXO to be redeemed will be passed to
            # the signature_format function, otherwise False is passed and the UTXO will be requested afterwards.
            o = orphan if not orphan else orphan.get(i)
            # The unsigned transaction is formatted depending on the input that is going to be signed. For input i,
            # the ScriptSig[i] will be set to the scriptPubKey of the UTXO that input i tries to redeem, while all
            # the other inputs will be set blank.
            unsigned_tx = self.signature_format(index[i], hashflag, o, network)

            # Then, depending on the format how the private keys have been passed to the signing function
            # and the content of the ScripSig field, a different final scriptSig will be created.
            if isinstance(sk[i], list) and unsigned_tx.scriptSig[index[i]].type == "P2MS":
                sigs = []
                for k in sk[i]:
                    sigs.append(ecdsa_tx_sign(
                        unsigned_tx.serialize(), k, hashflag, deterministic))
                iscript = InputScript.P2MS(sigs)
            elif isinstance(sk[i], SigningKey) and unsigned_tx.scriptSig[index[i]].type == "P2PK":
                s = ecdsa_tx_sign(unsigned_tx.serialize(),
                                  sk[i], hashflag, deterministic)
                iscript = InputScript.P2PK(s)
            elif isinstance(sk[i], SigningKey) and unsigned_tx.scriptSig[index[i]].type == "P2PKH":
                s = ecdsa_tx_sign(unsigned_tx.serialize(),
                                  sk[i], hashflag, deterministic)
                pk = serialize_pk(sk[i].get_verifying_key(), compressed)
                iscript = InputScript.P2PKH(s, pk)
            elif unsigned_tx.scriptSig[index[i]].type == "unknown":
                raise Exception(
                    "Unknown previous transaction output script type. Can't sign the transaction.")
            else:
                raise Exception("Can't sign input " + str(i) +
                                " with the provided data.")

            # Finally, temporal scripts are stored as final and the length of the script is computed
            self.scriptSig[i] = iscript
            self.scriptSig_len[i] = len(iscript.content) / 2

        self.hex = self.serialize()

    def signature_format(self, index, hashflag=SIGHASH_ALL, orphan=False, network='test'):
        """ Builds the signature format an unsigned transaction has to follow in order to be signed. Basically empties
        every InputScript field but the one to be signed, identified by index, that will be filled with the OutputScript
        from the UTXO that will be redeemed.

        The format of the OutputScripts will depend on the hashflag:
            - SIGHASH_ALL leaves OutputScript unchanged.
            - SIGHASH_SINGLE should sign each input with the output of the same index (not implemented yet).
            - SIGHASH_NONE empies all the outputs.
            - SIGHASH_ANYONECANPAY not sure about what should do (obviously not implemented yet).

        :param index: The index of the input to be signed.
        :type index: int
        :param hashflag: Hash type to be used, see above description for further information.
        :type hashflag: int
        :param orphan: Whether the input is orphan or not. Orphan inputs must provide an OutputScript that matches the
        utxo to be redeemed.
        :type orphan: OutputScript
        :param network: Network into which the transaction will be published (either mainnet or testnet).
        :type network: str
        :return: Transaction properly formatted to be signed.
        :rtype TX
        """

        tx = deepcopy(self)
        for i in range(tx.inputs):
            if i is index:
                if not orphan:
                    script, t = get_prev_ScriptPubKey(
                        tx.prev_tx_id[i], tx.prev_out_index[i], network)
                    # Once we get the previous UTXO script, the inputScript is temporarily set to it in order to sign
                    # the transaction.
                    tx.scriptSig[i] = InputScript.from_hex(script)
                    tx.scriptSig[i].type = t
                else:
                    # If input to be signed is orphan, the orphan InputScript is used when signing the transaction.
                    tx.scriptSig[i] = orphan
                tx.scriptSig_len[i] = len(tx.scriptSig[i].content) / 2
            elif tx.scriptSig[i].content != "":
                # All other scriptSig fields are emptied and their length is set to 0.
                tx.scriptSig[i] = InputScript()
                tx.scriptSig_len[i] = len(tx.scriptSig[i].content) / 2

        if hashflag is SIGHASH_SINGLE:
            # First we checks if the input that we are trying to sign has a corresponding output, if so, the execution
            # can continue. Otherwise, we abort the signature process since it could lead to a irreversible lose of
            # funds due to a bug in SIGHASH_SINGLE.
            # https://bitcointalk.org/index.php?topic=260595

            if index >= tx.outputs:
                raise Exception("You are trying to use SIGHASH_SINGLE to sign an input that does not have a "
                                "corresponding output (" + str(index) +
                                "). This could lead to a irreversible lose "
                                "of funds. Signature process aborted.")
            # Otherwise, all outputs will set to empty scripts but the ith one (identified by index),
            # since SIGHASH_SINGLE should only sign the ith input with the ith output.
            else:
                # How to properly deal with SIGHASH_SINGLE signature format extracted from:
                # https://github.com/bitcoin/bitcoin/blob/3192e5278a/test/functional/test_framework/script.py#L869

                # First we backup the output that we will sign,
                t_script = tx.scriptPubKey[index]
                t_size = tx.scriptPubKey_len[index]
                t_value = tx.value[index]

                # Then, we delete every single output.
                tx.scriptPubKey = []
                tx.scriptPubKey_len = []
                tx.value = []
                for o in range(index):
                    # Once the all outputs have been deleted, we create empty outputs for every single index before
                    # the one that will be signed. Furthermore, the value of the output if set to maximum (2^64-1)
                    tx.scriptPubKey.append(OutputScript())
                    tx.scriptPubKey_len.append(
                        len(tx.scriptPubKey[o].content) / 2)
                    tx.value.append(pow(2, 64) - 1)

                # Once we reach the index of the output that will be signed, we restore it with the one that we backed
                # up before.
                tx.scriptPubKey.append(t_script)
                tx.scriptPubKey_len.append(t_size)
                tx.value.append(t_value)

                # Finally, we recalculate the number of outputs for the signature format.
                # Notice that each signature format will have index number of outputs! Otherwise it will be invalid.
                tx.outputs = len(tx.scriptPubKey)

        elif hashflag is SIGHASH_NONE:
            # Empty all the scriptPubKeys and set the length and the output counter to 0.
            tx.outputs = 0
            tx.scriptPubKey = OutputScript()
            tx.scriptPubKey_len = len(tx.scriptPubKey.content) / 2

        elif hashflag is SIGHASH_ANYONECANPAY:
            # ToDo: Implement SIGHASH_ANYONECANPAY
            pass

        if hashflag in [SIGHASH_SINGLE, SIGHASH_NONE]:
            # All the nSequence from inputs except for the current one (index) is set to 0.
            # https://github.com/bitcoin/bitcoin/blob/3192e5278a/test/functional/test_framework/script.py#L880
            for i in range(tx.inputs):
                if i is not index:
                    tx.nSequence[i] = 0

        return tx

    def display(self):
        """ Displays all the information related to the transaction object, properly split and arranged.

        Data between parenthesis corresponds to the data encoded following the serialized transaction format.
        (replicates the same encoding being done in serialize method)

        :param self: self
        :type self: TX
        :return: None.
        :rtype: None
        """

        print("version: " + str(self.version) +
              " (" + change_endianness(int2bytes(self.version, 4)) + ")")
        print("number of inputs: " + str(self.inputs) +
              " (" + encode_varint(self.inputs) + ")")
        for i in range(self.inputs):
            print("input " + str(i))
            print("\t previous txid (little endian): " +
                  self.prev_tx_id[i] + " (" + change_endianness(self.prev_tx_id[i]) + ")")
            print("\t previous tx output (little endian): " +
                  str(self.prev_out_index[i]) + " (" + change_endianness(int2bytes(self.prev_out_index[i], 4)) + ")")
            print("\t input script (scriptSig) length: " +
                  str(self.scriptSig_len[i]) + " (" + encode_varint((self.scriptSig_len[i])) + ")")
            print("\t input script (scriptSig): " + self.scriptSig[i].content)
            print("\t decoded scriptSig: " +
                  Script.deserialize(self.scriptSig[i].content))
            if self.scriptSig[i].type == "P2SH":
                print("\t \t decoded redeemScript: " +
                      InputScript.deserialize(self.scriptSig[i].get_element(-1)[1:-1]))
            print("\t nSequence: " +
                  str(self.nSequence[i]) + " (" + int2bytes(self.nSequence[i], 4) + ")")
        print("number of outputs: " + str(self.outputs) +
              " (" + encode_varint(self.outputs) + ")")
        for i in range(self.outputs):
            print("output " + str(i))
            print("\t Satoshis to be spent (little endian): " +
                  str(self.value[i]) + " (" + change_endianness(int2bytes(self.value[i], 8)) + ")")
            print("\t output script (scriptPubKey) length: " +
                  str(self.scriptPubKey_len[i]) + " (" + encode_varint(self.scriptPubKey_len[i]) + ")")
            print("\t output script (scriptPubKey): " +
                  self.scriptPubKey[i].content)
            print("\t decoded scriptPubKey: " +
                  Script.deserialize(self.scriptPubKey[i].content))

        print("nLockTime: " + str(self.nLockTime) +
              " (" + int2bytes(self.nLockTime, 4) + ")")

#################################################
#           Hex transaction analysis            #
#################################################

# ---------------------------------------------------------------------------------------------------------------------
# The following piece of code parses a serialized transaction (hex encoded) and displays all the information related
# to it.
# - Leftmost displayed transaction shows data as should be interpreted (human-readable), while rightmost
# (surrounded by parenthesis) shows it as it is in the serialize transaction (can be used to identify it inside the
# transaction)
# - You should change the hex_tx for the one you'd like to deserialize. Serialized transaction can be obtain from block
# explorers such as blockcypher.com or blockchain.info, or by building a transaction using some of the library tools.
# ---------------------------------------------------------------------------------------------------------------------


# First a transaction object is created (through the deserialize constructor) by deserializing the hex transaction we
# have selected.
if __name__ == "__main__":

    hex_tx = "01000000013ca58d2f6fac36602d831ee0cf2bc80031c7472e80a322b57f614c5ce9142b71000000006b483045022100f0331d85cb7f7ec1bedc41f50c695d654489458e88aec0076fbad5d8aeda1673022009e8ca2dda1d6a16bfd7133b0008720145dacccb35c0d5c9fc567e52f26ca5f7012103a164209a7c23227fcd6a71c51efc5b6eb25407f4faf06890f57908425255e42bffffffff0241a20000000000001976a914e44839239ab36f5bc67b2079de00ecf587233ebe88ac74630000000000001976a914dc7016484646168d99e49f907c86c271299441c088ac00000000"
    tx = TX.deserialize(hex_tx)

    # Then, the transaction can be displayed using the display method to analyze how it's been constructed.
    tx.display()
