from hd_wallet import HDWallet


PATH = 'm/40/10/134'


print("\n---- Mainnet ----")
print("symbol: DOGE")

xpub = 'dgub8kXBZ7ymNWy2RKqyrtun4BKWC5w12ChzSjiYYYjegnpE6PcYvSAuL1YnWEQVKQXgmiBbFLj2GWir1MmXvZ5Kv7Q7boRf3xMRqSvYfnFyyoT'
print("xpub: {}".format(xpub))

hd = HDWallet.from_xpublic_key(xpublic_key=xpub, symbol="DOGE")
hd = hd.subkey_at_public_derivation(path=PATH)

print("PATH: {}".format(PATH))
print("\tpublic key: {}".format(hd.public_key()))
print("\tp2pkh address: {}".format(hd.p2pkh_address()))


######################
#     TESTNET
######################

print("\n---- Testnet ----")
print("symbol: DOGETEST")

xpub = 'tpubD6NzVbkrYhZ4X9vUsAuJeJEWfRMjQbSe9bcvjVKk3j3GiM3qeKByCDCEe5d4VkbAoNTBqMiakD83g3iwseuxoAH3RF1E46532ZpA6tSWsUS'
print("xpub: {}".format(xpub))

hd = HDWallet.from_xpublic_key(xpublic_key=xpub, symbol="DOGETEST")
hd = hd.subkey_at_public_derivation(path='m/40/10/134')

print("PATH: {}".format(PATH))
print("\tpublic key: {}".format(hd.public_key()))
print("\tp2pkh address: {}".format(hd.p2pkh_address()))