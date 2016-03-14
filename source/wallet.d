import std.stdio;
import std.string;
import std.getopt;
import std.range;
import std.algorithm;
import std.algorithm.mutation;
import core.stdc.stdlib;
import deimos.openssl.bn;
import deimos.openssl.sha;

import words;

BIGNUM* create_seed() {
	auto rnd = BN_new();
	BN_rand(rnd, 128, -1, 0);

	auto hex = fromStringz(BN_bn2hex(rnd));
	writefln("seed: %s", hex);

	auto mnemonic = get_mnemonic(rnd);
	writefln("mnemonic: %s", mnemonic);

	return rnd;
}

const auto cs = 4;

string get_mnemonic(BIGNUM* num) {
	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	ubyte[16] ba;
	BN_bn2bin(num, ba.ptr);
	SHA256_Update(&sha_ctx, ba.ptr, ba.length);
	ubyte[32] sha;
	SHA256_Final(sha.ptr, &sha_ctx);

	auto sha_bn = BN_bin2bn(sha.ptr, sha.length, null);

	BN_lshift(num, num, cs);
	BN_rshift(sha_bn, sha_bn, 256-cs);
	BN_add(num, num, sha_bn);

	auto mnemonic = iota(0, 12).map!(delegate string(int _) {
		auto c = BN_dup(num);
		BN_mask_bits(c, 11);
		BN_rshift(num, num, 11);
		return word_list[BN_get_word(c)]; }).array;
	mnemonic.reverse();
	auto s = mnemonic.join(" ");
	return s;
}

BIGNUM* get_entropy(string mnemonic) {
	auto seed = BN_new();
	BN_zero(seed);
	mnemonic.split(" ").each!(delegate void(string word) {
		BN_lshift(seed, seed, 11);
		BN_add_word(seed, words_hash[word]);
		});

	BN_rshift(seed, seed, 4);
	return seed;
}