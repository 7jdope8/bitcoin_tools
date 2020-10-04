from bitcoin_tools.core.transaction import TX

#################################################
#           Hex transaction analysis            #
#################################################

# https://github.com/bitcoin/bitcoin/blob/v0.13.1rc2/src/primitives/transaction.h#L275
"""/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CTxWitness wit;
 * - uint32_t nLockTime
 */"""
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
hex_tx = "020000000001018b0795ef60c78761001f5544e7d3910d63f9db2e0d6ed5f83b308e7f8d8f0fae0000000000fdffffff02734ef40100000000160014ad57609ab92acbd3c1b5b0e2aae15ba6da7eabec10201600000000001600140e7b71cb408a98f9ccd7402a557763178950954e0247304402204efc5ed1e980f5f1a3078c5a6c19c3e85f5bd7dbddd5d6c4a13ea7ccc0fab42f022043d00773037129c6e15b87ecd7d70e429b9df7a2906e16c50241131941b3bfdc012102d58aca4317df9be3801285859bfcaf768d0a91260432c105d6b25d457d553520acec0900"
# hex_tx = "02000000 # version
# varint/1b 00 # number of vins ??? /marker char https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki Must be zero
# 1 byte    01 # vin data ???? /flag char bip-0144 Must be non-zero
# varint    01 # number of vouts ??? /txin count varint bip-0144
# 32 bytes  8b0795ef60c78761001f5544e7d3910d63f9db2e0d6ed5f83b308e7f8d8f0fae # vin vout txid/hash little endian
# 4 bytes   00000000 # vin vout index
#           00 # script bytes
#           fdffffff # Sequence number ???
#           02 # vout count
# 8 bytes   734ef401 # 32 788 083 Satoshis vout n0 value little endian
#           00 # bytes in pk_script ???
#           000000160014
#           ad57609ab92acbd3c1b5b0e2aae15ba6da7eabec # vout n0 scriptPubKey asm
# 8 bytes   10201600 # 1 450 000 Satoshis vout n1 value little endian
#           00 # bytes in pk_script ???
#           000000160014
#           0e7b71cb408a98f9ccd7402a557763178950954e # vout n1 scriptPubKey asm
#           02 # count of whitness?
#           47 # varint len in bytes (71 DEC)
#           304402204efc5ed1e980f5f1a3078c5a6c19c3e85f5bd7dbddd5d6c4a13ea7ccc0fab42f022043d00773037129c6e15b87ecd7d70e429b9df7a2906e16c50241131941b3bfdc01
#           21 # varint len in bytes (33 DEC)
#           02d58aca4317df9be3801285859bfcaf768d0a91260432c105d6b25d457d553520
#           acec0900" # nLockTime
tx = TX.deserialize(hex_tx)

# Then, the transaction can be displayed using the display method to analyze how it's been constructed.
tx.display()
