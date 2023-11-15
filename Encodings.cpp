#include "Encodings.h"

#include "Base64.hpp"

string encodings::wchar_to_string(const wchar_t* pwchar) {
	if (!pwchar) return string();
	const wstring ws(pwchar);
	return encodings::utf8_decode(ws);
}

string encodings::utf8_decode(const wstring& wstr) {
	if (wstr.empty()) return string();
	const int wstrSize = wstr.size();
	const int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), wstrSize, NULL, 0, NULL, NULL);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.data(), wstrSize, strTo.data(), size_needed, NULL, NULL);
	return strTo;
}


wstring encodings::utf8_encode(const string& str) {
	if (str.empty()) return wstring();
	const int strSize = str.size();
	const int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), strSize, NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.data(), strSize, wstrTo.data(), size_needed);
	return wstrTo;
}

LibsodiumKey crypt::keygen() {
	LibsodiumKey key;
	randombytes_buf(key.data(), key.max_size());
	return key;
}

bool crypt::gen_kx_keypair(LibsodiumKey& pk, LibsodiumKey& sk) noexcept {
	return crypto_kx_keypair(pk.data(), sk.data()) == SODIUM_SUCCESS;
}

byte_array crypt::random_bytes(const size_t size) {
	byte_array buffer(size);
	randombytes_buf(static_cast<PVOID>(buffer.data()), size);
	return buffer;
}

string crypt::random_string(const string::size_type length, const string_view charset) {
	std::string tmp_s;
	tmp_s.reserve(length);
	const string::size_type maxIndex = charset.size() - 1;
	for (string::size_type i = 0; i < length; ++i) {
		tmp_s += charset[rand() % maxIndex];
	}
	return tmp_s;
}

string crypt::random_bytes_string(const size_t size) {
	string buffer;
	buffer.resize(size);
	randombytes_buf(static_cast<PVOID>(buffer.data()), size);
	return buffer;
}

Blake2bHash crypt::HashGenerator::hashGen(const uint8_t* in, const size_t insize) const {
	Blake2bHash hash;
	randombytes_buf(hash.data(), crypto_generichash_blake2b_SALTBYTES);
	if (crypto_generichash_blake2b_salt_personal(
		hash.data() + crypto_generichash_blake2b_SALTBYTES, BLAKE2B_DIGEST_SIZE,
		in, insize,
		this->mKey.data(), this->mKey.size(), hash.data(), NULL) != SODIUM_SUCCESS) {
		throw std::runtime_error("Failed to hash blake2b message");
	}
	return hash;
}

Blake2bHash crypt::HashGenerator::hashGen(const string& input) const {
	return this->hashGen(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

bool crypt::HashGenerator::hashVerify(const Blake2bHash& hash, const uint8_t* in, const size_t insize) const {
	Blake2bHash h;
	memcpy_s(h.data(), h.size(), hash.data(), crypto_generichash_blake2b_SALTBYTES);
	if (crypto_generichash_blake2b_salt_personal(
		h.data() + crypto_generichash_blake2b_SALTBYTES, BLAKE2B_DIGEST_SIZE,
		in, insize,
		this->mKey.data(), this->mKey.size(), h.data(), NULL) != SODIUM_SUCCESS) {
		return false;
	}
	return h == hash;
}

Sha256Digest crypt::sha256(const uint8_t* message, const size_t messageLength) {
	Sha256Digest hash;
	if (crypto_hash_sha256(hash.data(), message, messageLength) != SODIUM_SUCCESS) {
		throw std::runtime_error("Failed to hash sha256 message");
	}
	return hash;
}
Sha256Digest crypt::sha256(const string& input) {
	return crypt::sha256(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}
Sha256Digest crypt::sha256(const byte_array& input) {
	return crypt::sha256(input.data(), input.size());
}

Sha512Digest crypt::sha512(const uint8_t* message, const size_t messageLength) {
	Sha512Digest hash;
	if (crypto_hash_sha512(hash.data(), message, messageLength) != SODIUM_SUCCESS) {
		throw std::runtime_error("Failed to hash sha256 message");
	}
	return hash;
}
Sha512Digest crypt::sha512(const string& input) {
	return crypt::sha512(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}
Sha512Digest crypt::sha512(const byte_array& input) {
	return crypt::sha512(input.data(), input.size());
}

optional<byte_array> crypt::XChaCha20Poly1305::encrypt(const uint8_t* plaintext, const size_t plaintextSize) const {
	uint64_t ciphertextLen = crypto_aead_xchacha20poly1305_ietf_ABYTES + plaintextSize;
	byte_array ciphertext(
		crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ciphertextLen
	);
	randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	if (crypto_aead_xchacha20poly1305_ietf_encrypt(
		ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, &ciphertextLen,
		plaintext, plaintextSize,
		NULL, 0,
		NULL, ciphertext.data(), this->mKey.data()
	) != SODIUM_SUCCESS) {
		return nullopt;
	}
	return ciphertext;
}

optional<byte_array> crypt::XChaCha20Poly1305::encrypt(const string& plaintext) const {
	return this->encrypt(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
}

optional<byte_array> crypt::XChaCha20Poly1305::encrypt(const msgpack::sbuffer& plaintext) const {
	return this->encrypt(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
}

optional<byte_array> crypt::XChaCha20Poly1305::decrypt(const uint8_t* ciphertext, const size_t ciphertextSize) const {
	uint64_t plaintextLen = ciphertextSize - crypto_aead_xchacha20poly1305_ietf_ABYTES - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	byte_array plaintext(plaintextLen);

	if (crypto_aead_xchacha20poly1305_ietf_decrypt(
		plaintext.data(), &plaintextLen,
		NULL,
		ciphertext + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, ciphertextSize - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
		NULL, 0,
		ciphertext, this->mKey.data()
	) != SODIUM_SUCCESS) {
		return nullopt;
	}
	return plaintext;
}

optional<byte_array> crypt::XChaCha20Poly1305::decrypt(const string& ciphertext) const {
	return this->decrypt(reinterpret_cast<const uint8_t*>(ciphertext.data()), ciphertext.size());
}

optional<byte_array> crypt::XChaCha20Poly1305::decrypt(const byte_array& ciphertext) const {
	return this->decrypt(ciphertext.data(), ciphertext.size());
}
static constexpr char_array::size_type BUFF_SIZE = 32768;

optional<string> encodings::compress(const Bytef* data, const size_t size, int compressionlevel) {

	z_stream zs;                        // z_stream is zlib's control structure
#ifdef _WIN32
	RtlSecureZeroMemory(&zs, sizeof(zs));
#else
	memset(&zs, 0, sizeof(zs));
#endif

	if (deflateInit(&zs, compressionlevel) != Z_OK) return nullopt;

	zs.next_in = data;
	zs.avail_in = size;           // set the z_stream's input

	int ret;
	char_array outbuffer(BUFF_SIZE);
	string outstring;
	// retrieve the compressed bytes blockwise
	do {
		zs.next_out = reinterpret_cast<Bytef*>(outbuffer.data());
		zs.avail_out = outbuffer.size();

		ret = deflate(&zs, Z_FINISH);

		if (outstring.size() < zs.total_out) {
			// append the block to the output string
			outstring.append(outbuffer.data(), zs.total_out - outstring.size());
		}
	} while (ret == Z_OK);

	deflateEnd(&zs);

	if (ret == Z_STREAM_END) return outstring;

	return nullopt;
}

optional<string> encodings::compress(const string& str, int compressionlevel) {
	return encodings::compress(reinterpret_cast<const Bytef*>(str.data()), str.size(), compressionlevel);
}

optional<string> encodings::compress(const byte_array& in, int compressionlevel) {
	return encodings::compress(in.data(), in.size(), compressionlevel);
}

optional<string> encodings::decompress(const Bytef* data, const size_t size) {
	z_stream zs;                        // z_stream is zlib's control structure
#ifdef _WIN32
	RtlSecureZeroMemory(&zs, sizeof(zs));
#else
	memset(&zs, 0, sizeof(zs));
#endif

	if (inflateInit(&zs) != Z_OK) return nullopt;

	zs.next_in = data;
	zs.avail_in = size;           // set the z_stream's input

	int ret;
	char_array outbuffer(BUFF_SIZE);
	string outstring;
	// retrieve the compressed bytes blockwise
	do {
		zs.next_out = reinterpret_cast<Bytef*>(outbuffer.data());
		zs.avail_out = outbuffer.size();

		ret = inflate(&zs, Z_NO_FLUSH);

		if (outstring.size() < zs.total_out) {
			// append the block to the output string
			outstring.append(outbuffer.data(), zs.total_out - outstring.size());
		}
	} while (ret == Z_OK);

	inflateEnd(&zs);

	if (ret == Z_STREAM_END) return outstring;

	return nullopt;
}

optional<string> encodings::decompress(const byte_array& str) {
	return encodings::decompress(str.data(), str.size());
}

optional<string> encodings::decompress(const string& str) {
	return encodings::decompress(reinterpret_cast<z_const Bytef*>(str.data()), str.size());
}
