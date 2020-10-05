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
# hex_tx = "020000000001018b0795ef60c78761001f5544e7d3910d63f9db2e0d6ed5f83b308e7f8d8f0fae0000000000fdffffff02734ef40100000000160014ad57609ab92acbd3c1b5b0e2aae15ba6da7eabec10201600000000001600140e7b71cb408a98f9ccd7402a557763178950954e0247304402204efc5ed1e980f5f1a3078c5a6c19c3e85f5bd7dbddd5d6c4a13ea7ccc0fab42f022043d00773037129c6e15b87ecd7d70e429b9df7a2906e16c50241131941b3bfdc012102d58aca4317df9be3801285859bfcaf768d0a91260432c105d6b25d457d553520acec0900"
# hex_tx = "0200000000010178f480d25895817cd5537ddb431be44c3464d886800c5dd749eb852133762ab10000000000fdffffff04c10500000000000016001475bce781270c3624f8cbe1d52dc42b3c8bf09d2853991600000000001600142d4d9e741d301a94d055e402d316ce282cee2234feb21f0100000000160014aaba350dd348de07c4fa60eae1664d859a669ae421c0bd000000000017a91482b4a28bb4f207d60db3429ed474dd68ad055f3e870247304402201eb810896a2c9f601442342314cd31bec556d4e2f0ec81b1303046f8e1e0c4010220040f1c8de93ee9cd55ff9441129f9f8ca12752bb4e917d9ee804f1ce3adf7a2e012103ffb9a5fae765acb979308f88d1a498972f0198fb39b4a8e7286a5ac392b59cde6ef00900"
hex_tx = '02000000000104564cbd188db7178dac57cf7a5fd09812c947a5cfb75d66a1a46ca27465fc21b10000000017160014c3eb4c03b0df78ffc211f72ea8d08d0eca74e281fdffffff672e57b9693ca48089016849aa809a189d75f4982422c00baf5bfa05ceb11db90100000017160014fd074bd35ce52c61f8855b61ed72c690923e5a87fdffffffbed5f7848ae630b804a6f7732059d3fc1d86df8def8a9bf014ded8c274dcffb80c000000171600140de01b667a614191920b4686dea2db8973bb35bafdffffffe58cfb3212e988e05682e4dd4530239e7913455755ea41358e6ee87e3d48692400000000171600141d9764cb5906eaa5c07a987624f93189f287971bfdffffff010065cd1d0000000017a9144d856ff4875decf91c413f194de7ec38859a7a3c87024730440220338f13d154910ceef62039753a0d3394ad6715b45bbc9945a5d1b31899a8a6b602206bb4371b204ccd1a9da759188feff7ba268540c4c0c65a2632fa9eddc14ce60a0121036b7ed62f4026d8a484640953af4490f866565875f8c4c952114aa71c42e21aac0247304402205bead2ee73bfec6fc879a185e30d1f1cf901df46cc8a7e715baf1a2d5801267102200268cca107105b7d1e40879250c1e6b08418b37773a1ceba323340c7b946fd0e012103e162a4070a16a73d44d00e66abaf639eacf48a8c38108656622d842bb7873a030247304402203e3adbee9e095153ae16b47de13a69d534aa3eb0f194e7b870be75b34c9df657022027f67be4ce4f480c8e60e51c132ec1949f887edee1c80e87e2f299b632e1290b012103803fe60d6e9497ba760ae71c7924eabdf2673c299ef2f9df4bb8c87797e6b3bd0247304402207e6160a5a90c6ea4855d71acb4803a30661001d81f754b00a786a830f7e3bbd302201a7a1b7832f716dbbd12bb378bdfe5f6172988550832a64d1d03d1e1a4cf44ae012103dd39b5b603fc1eac34a371c6f3f3a419bd2098bb7c80b45738260c9402dfdb8a73f00900'

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
while hex_tx:

    tx = TX.deserialize(hex_tx)

    # Then, the transaction can be displayed using the display method to analyze how it's been constructed.
    tx.display()
    print('\n\n')
    hex_tx = input('raw tx, please: ')

# todo!

# vout witness_v0_keyhash type?
# bc1 addresses
