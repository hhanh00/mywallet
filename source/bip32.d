import std.stdio;
import std.string;
import std.getopt;
import std.range;
import std.range.primitives;
import std.algorithm;
import std.algorithm.mutation;
import std.conv;
import std.bitmanip;
import std.outbuffer;
import std.exception;
import core.stdc.stdlib;
import deimos.openssl.bn;
import deimos.openssl.sha;
import deimos.openssl.ripemd;
import deimos.openssl.evp;
import deimos.openssl.ec;
import deimos.openssl.hmac;
import deimos.openssl.engine;

import coins;

EC_GROUP* group;
BN_CTX* bn_ctx;
HMAC_CTX hmac_ctx;
ENGINE* engine;
BIGNUM* order;

static this() {
	group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	bn_ctx = BN_CTX_new();
	engine = ENGINE_get_digest_engine(NID_sha512);
	order = BN_new();
	EC_GROUP_get_order(group, order, bn_ctx);
}

auto hmac32(ubyte[] cc, ubyte[] data) {
	HMAC_Init_ex(&hmac_ctx, cc.ptr, to!int(cc.length), EVP_sha512, engine);
	HMAC_Update(&hmac_ctx, data.ptr, data.length);
	auto hash = new ubyte[64];
	auto length = to!uint(hash.length);
	HMAC_Final(&hmac_ctx, hash.ptr, &length);
	return hash;
}

class SecExt {
	BIGNUM* sk; // secret key
	ubyte[] cc; // chain code
	EC_KEY* key;

	this(BIGNUM* sk_, ubyte[] cc_) {
		sk = sk_;
		cc = cc_;

		key = EC_KEY_new();
		EC_KEY_set_group(key, group);
		EC_KEY_set_private_key(key, sk);
		auto pk = EC_POINT_new(group);
		scope(exit) EC_POINT_free(pk);
		EC_POINT_mul(group, pk, sk, null, null, bn_ctx);
		EC_KEY_set_public_key(key, pk);
	}

	~this() {
		BN_free(sk);
		EC_KEY_free(key);
	}

	SecExt derive_private_child(int index) {
		ubyte[37] buffer;
		if (index < 0) {
			buffer[0] = 0;
			BN_bn2bin(sk, buffer[1..33].ptr);
		}
		else {
			auto point = EC_KEY_get0_public_key(key);
			EC_POINT_point2oct(group, point, point_conversion_form_t.POINT_CONVERSION_COMPRESSED, 
				buffer.ptr, buffer.length, bn_ctx);
		}
		ubyte[] pb = buffer[33..$];
		pb.append!(int, Endian.bigEndian)(index);
		auto hash = hmac32(cc, buffer);

		auto delta = BN_new();
		scope(exit) BN_free(delta);
		BN_bin2bn(hash.ptr, 32, delta);
		auto new_sk = BN_new();
		BN_add(new_sk, sk, delta);
		BN_mod(new_sk, new_sk, order, bn_ctx);

		auto new_secext = new SecExt(new_sk, hash[32..$]);
		return new_secext;
	}

	void get_pk(ubyte[] pk) {
		auto point = EC_KEY_get0_public_key(key);
		EC_POINT_point2oct(group, point, point_conversion_form_t.POINT_CONVERSION_COMPRESSED, 
			pk.ptr, pk.length, bn_ctx);
	}

	override string toString() {
		string sk_s = fromStringz(BN_bn2hex(sk)).idup;
		auto bn_temp = BN_new();
		scope(exit) BN_free(bn_temp);
		BN_bin2bn(cc.ptr, 32, bn_temp);
		string cc_s = fromStringz(BN_bn2hex(bn_temp)).idup;

		return format("(%s,%s)", sk_s, cc_s);
	}
}

class PubExt {
	ubyte[] cc; // chain code
	EC_KEY* key;

	this(EC_POINT* pk_, ubyte[] cc_) {
		key = EC_KEY_new();
		EC_KEY_set_group(key, group);
		EC_KEY_set_public_key(key, pk_);
		cc = cc_;
	}

	~this() {
		EC_KEY_free(key);
	}

	this(string pk_s, string cc_s) {
		key = EC_KEY_new();
		EC_KEY_set_group(key, group);
		auto pk_bn = BN_new();
		scope(exit) BN_free(pk_bn);
		BN_hex2bn(&pk_bn, toStringz(pk_s));
		ubyte[33] pk_bin;
		BN_bn2bin(pk_bn, pk_bin.ptr);
		auto pk = EC_POINT_new(group);
		scope(exit) EC_POINT_free(pk);
		auto s = EC_POINT_oct2point(group, pk, pk_bin.ptr, 33, bn_ctx);
		EC_KEY_set_public_key(key, pk);

		auto cc_bn = BN_new();
		scope(exit) BN_free(cc_bn);
		BN_hex2bn(&cc_bn, toStringz(cc_s));
		auto cc_bin = new ubyte[32];
		BN_bn2bin(cc_bn, cc_bin.ptr);
		cc = cc_bin;
	}

	PubExt derive_public_child(int index) {
		ubyte[37] buffer;
		auto pb = buffer[];
		assert(index >= 0); // Cannot derive hardened key
		auto pk = EC_KEY_get0_public_key(key);
		EC_POINT_point2oct(group, pk, point_conversion_form_t.POINT_CONVERSION_COMPRESSED, 
			pb.ptr, pb.length, bn_ctx);
		pb.popFrontN(33);
		pb.append!(int, Endian.bigEndian)(index);

		auto hash = hmac32(cc, buffer);
		auto delta = BN_new();
		scope(exit) BN_free(delta);
		BN_bin2bn(hash.ptr, 32, delta);

		auto one = BN_new();
		scope(exit) BN_free(one);
		BN_one(one);
		auto new_pk = EC_POINT_new(group);
		EC_POINT_mul(group, new_pk, delta, pk, one, bn_ctx);

		return new PubExt(new_pk, hash[32..$]);
	}

	override string toString() {
		ubyte[33] buffer;
		auto pk = EC_KEY_get0_public_key(key);
		assert(pk !is null);
		EC_POINT_point2oct(group, pk, point_conversion_form_t.POINT_CONVERSION_COMPRESSED, 
			buffer.ptr, buffer.length, bn_ctx);
		auto bn_temp = BN_new();
		scope(exit) BN_free(bn_temp);
		BN_bin2bn(buffer.ptr, 33, bn_temp);
		string pk_s = fromStringz(BN_bn2hex(bn_temp)).idup;
		BN_bin2bn(cc.ptr, 32, bn_temp);
		string cc_s = fromStringz(BN_bn2hex(bn_temp)).idup;

		return format("(%s,%s)", pk_s, cc_s);
	}
}

SecExt get_seed(string mnemonic, string password) {
	string salt = "mnemonic" ~ password;
	ubyte[64] seed;

	PKCS5_PBKDF2_HMAC(mnemonic.ptr, to!int(mnemonic.length), 
		cast(ubyte*)(salt.ptr), to!int(salt.length), 2048,
		EVP_sha512,
		64, seed.ptr);

	auto sk = BN_new();
	BN_bin2bn(seed.ptr, 32, sk);
	auto cc = seed[32..$].dup();

	return new SecExt(sk, cc);
}

SecExt get_coin_key(SecExt master, int coin) {
	return master
		.derive_private_child(0x8000002C)
		.derive_private_child(0x80000000 + coin)
		.derive_private_child(0x80000000);
}

string pk_to_address(const EC_POINT* pk, ubyte prefix) {
	ubyte[33] buffer;
	EC_POINT_point2oct(group, pk, point_conversion_form_t.POINT_CONVERSION_COMPRESSED, 
		buffer.ptr, buffer.length, bn_ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, buffer.ptr, buffer.length);
	ubyte[32] sha;
	SHA256_Final(sha.ptr, &sha_ctx);

	RIPEMD160_CTX ripe_ctx;
	RIPEMD160_Init(&ripe_ctx);
	RIPEMD160_Update(&ripe_ctx, sha.ptr, 32);
	ubyte[20] ripemd;
	RIPEMD160_Final(ripemd.ptr, &ripe_ctx);

	return ripemd_to_address(ripemd, prefix);
}

ubyte[] double_sha(ubyte[] data) {
	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, data.ptr, data.length);
	auto sha = new ubyte[32];
	SHA256_Final(sha.ptr, &sha_ctx);
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, sha.ptr, 32);
	SHA256_Final(sha.ptr, &sha_ctx);

	return sha;	
}

string ripemd_to_address(ubyte[] ripemd, ubyte prefix) {
	ubyte[25] address_bin;
	address_bin[0] = prefix;
	address_bin[1..21] = ripemd;

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, address_bin.ptr, 21);
	ubyte[] sha = double_sha(address_bin[0..21]);
	address_bin[21..25] = sha[0..4];

	return base58_encode(address_bin);
}

string base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

string base58_encode(ubyte[] data) {
	auto leading_zero_count = data.countUntil!"a != 0"(0);
	string ones = repeat("1", leading_zero_count).join();
	auto address_appender = appender("");
	auto bn = BN_new();
	BN_bin2bn(data.ptr, to!int(data.length), bn);
	while (true) {
		if (BN_is_zero(bn))
			break;
		auto m = BN_mod_word(bn, 58);
		address_appender.append(base58_alphabet[m]);
		BN_div_word(bn, 58);
	}

	auto s = address_appender.data.dup;
	s.reverse();
	auto address = ones ~ s;

	return assumeUnique(address);
}

string sk_to_wip(const BIGNUM* sk, ubyte prefix) {
	ubyte[38] sk_bin;
	sk_bin[0] = prefix | 0x80;
	BN_bn2bin(sk, sk_bin[1..33].ptr);
	sk_bin[33] = 0x01;
	ubyte[] sha = double_sha(sk_bin[0..34]);
	sk_bin[34..38] = sha[0..4];

	return base58_encode(sk_bin);
}