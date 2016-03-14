import std.stdio;
import std.string;
import std.getopt;
import std.json;
import std.conv;
import core.stdc.stdlib;
import deimos.openssl.bn;
import deimos.openssl.ec;

import wallet;
import bip32;
import coins;

void main(string[] args)
{
	string password = "";
	string mnemonic = "";
	string mpk = "";
	int count = 10;

	void check_mnemonic() {
		if (mnemonic == "") {
			writeln("Missing mnemonic");
			exit(1);
		}
	}

	auto help_info = getopt(
		args,
		"password", &password,
		"mnemonic", &mnemonic,
		"mpk", &mpk,
		"count", &count,
		);

	if (args.length < 2) {
		writeln("Missing command");
		exit(1);
	}

	string command = args[1];
	final switch (command) {
		case "seed":
			create_seed();
			break;

		case "entropy":
			check_mnemonic();
			auto entropy = get_entropy(mnemonic);
			writefln("entropy %s", fromStringz(BN_bn2hex(entropy)));
			break;

		case "mpk":
			check_mnemonic();
			auto seed = get_seed(mnemonic, password);
			auto k = get_coin_key(seed, Coins.BTC);
			ubyte[33] pk;
			k.get_pk(pk);
			auto bn_temp = BN_new();
			BN_bin2bn(pk.ptr, 33, bn_temp);
			auto pk_s = fromStringz(BN_bn2hex(bn_temp)).idup;
			BN_bin2bn(k.cc.ptr, 32, bn_temp);
			auto cc_s = fromStringz(BN_bn2hex(bn_temp)).idup;
			auto jv = JSONValue(["pub": pk_s, "chain": cc_s]);
			writeln(jv);
			break;

		case "receive":
			if (mpk == "") {
				writeln("Missing master public key");
				exit(1);
			}
			auto jv = parseJSON(mpk);
			auto pk_s = jv["pub"].str;
			auto cc_s = jv["chain"].str;
			auto master_pk = new PubExt(pk_s, cc_s);
			auto receive_list = master_pk.derive_public_child(0);
			foreach (i; 0..count) {
				auto receive_pk_ext = receive_list.derive_public_child(i);
				auto pk = EC_KEY_get0_public_key(receive_pk_ext.key);
				auto address = pk_to_address(pk, Coins.BTC);
				writefln("Address: %s", address);
			}
			break;

		case "keys": 
			check_mnemonic();
			auto seed = get_seed(mnemonic, password);
			auto k = get_coin_key(seed, Coins.BTC);
			auto receive_list = k.derive_private_child(0);
			foreach (i; 0..count) {
				auto receive_sk_ext = receive_list.derive_private_child(i);
				auto sk = EC_KEY_get0_private_key(receive_sk_ext.key);
				auto wip = sk_to_wip(sk, to!ubyte(Coins.BTC));
				writefln("WIP: %s", wip);
			}
			break;
	}
}

