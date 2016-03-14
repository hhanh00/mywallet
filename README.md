My wallet is a small BIP-32 key/address generator. I don't use it for anything really fancy but I got fed up of complex wallet
applications that suddenly become incompatible with their previous versions or are simply abandonned.

My wallet follows 

- BIP 39 for the generation of the master key from a list of mnemonic words,
- BIP 44 for the structure of the hierarchical wallet
- and BIP 32.

There are 5 commands.

1. `seed`: Generate a new random seed and prints out the mnemonic phrase. Keep it safe. Preferably offline.

```
vagrant@vagrant-ubuntu-trusty-64:~/mywallet$ ./mywallet seed
seed: D1282999B6BD2A0D6B3A2BE2E2E242BD
mnemonic: spell donor grid hope sport allow provide earth title blade mouse kit
```

2. `entropy`: Prints out the 128-bit random number associated with a given phrase.

```
vagrant@vagrant-ubuntu-trusty-64:~/mywallet$ ./mywallet --mnemonic 'spell donor grid hope sport allow provide earth title blade mouse kit' entropy
entropy D1282999B6BD2A0D6B3A2BE2E2E242BD
```

3. `mpk`: Prints out the master public key associated with a given phrase and optionally protected by a password.

```
vagrant@vagrant-ubuntu-trusty-64:~/mywallet$ ./mywallet --mnemonic 'spell donor grid hope sport allow provide earth title blade mouse kit' --password h mpk
{"chain":"B44A535D094E7BC68FFA1CEA7A69CCE31112D01B6435454747415975A2CD220B","pub":"03EEB2148F80C4984ECA379F1FB585A501115958814CB94E92F099B522549D4D27"}
```

Having the mpk is enough for generating addresses.

4. `receive`: Prints out a set of addresses from a given mpk.

```
vagrant@vagrant-ubuntu-trusty-64:~/mywallet$ ./mywallet --mpk '{"chain":"B44A535D094E7BC68FFA1CEA7A69CCE31112D01B6435454747415975A2CD220B","pub":"03EEB2148F80C4984ECA379F1FB585A501115958814CB94E92F099B522549D4D27"}' --count 1 receive
Address: 1Ek8WPAySjF9aLsK7DJWWsH1xLa8HFLYck
```

5. `keys`: Prints out the secret keys in WIP format for import in a wallet app, given the secret phrase and the password.

```
vagrant@vagrant-ubuntu-trusty-64:~/mywallet$ ./mywallet --mnemonic 'spell donor grid hope sport allow provide earth title blade mouse kit' --count 1 --password h keys
WIP: KwNrDC3H6iqZhQ5KWoZTXiuYGJLCASfG9ofQ4Vgx6HV1MeGhbEU5
```

