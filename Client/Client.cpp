#ifndef _CLIENT_H_
#define _CLIENT_H_

// Remove for production
#define DEBUG
#ifdef DEBUG
#define DEBUG_LOG(msg) do { std::cout << msg << std::endl; } while(0);
#endif


#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>

#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/integer.h"
#include "cryptopp/modes.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/secblock.h"

using CryptoPP::Integer;
using CryptoPP::RSA;

// For understanding purposes only
std::string hash_file(const std::string& file_name) {
  std::string digest;
  CryptoPP::SHA256 sha256;
  CryptoPP::HashFilter hf(sha256, new CryptoPP::StringSink(digest));

  char char_block[512] = {'\0'};

  std::ifstream file(file_name);

  file.read(char_block, sizeof(char_block));

  while(file.gcount() > 0) {
    hf.Put((byte const*)char_block, file.gcount());
    file.read(char_block, sizeof(char_block));
  }
  hf.MessageEnd();

  return digest;
}

std::string hash_file_stream(const std::string& file_name) {
  std::string digest;
  CryptoPP::SHA256 sha256;
  CryptoPP::FileSource fs(file_name.c_str(), true /* PumpAll */,
    new CryptoPP::HashFilter(sha256,
      new CryptoPP::StringSink(digest)
    ) // HashFilter
  ); // FileSource
  return digest;
}

void generate_pub_pvt_key_pair() {
  // InvertibleRSAFunction is used directly only because the private key
  // won't actually be used to perform any cryptographic operation;
  // otherwise, an appropriate typedef'ed type from rsa.h would have been used.
  CryptoPP::AutoSeededRandomPool rng;
  RSA::PrivateKey privkey;
  privkey.Initialize(rng, 3072, 3);

  // With the current version of Crypto++, MessageEnd() needs to be called
  // explicitly because Base64Encoder doesn't flush its buffer on destruction.
  CryptoPP::Base64Encoder privkeysink(new CryptoPP::FileSink("privkey.txt"));
  privkey.DEREncode(privkeysink);
  privkeysink.MessageEnd();

  // Suppose we want to store the public key separately,
  // possibly because we will be sending the public key to a third party.
  RSA::PublicKey pubkey(privkey);

  CryptoPP::Base64Encoder pubkeysink(new CryptoPP::FileSink("pubkey.txt"));
  pubkey.DEREncode(pubkeysink);
  pubkeysink.MessageEnd();
}

Integer generate_r(Integer& n) {
  Integer r;
  // Scratch Area

  DEBUG_LOG("Bitcount:");
  DEBUG_LOG(n.BitCount());

  CryptoPP::AutoSeededRandomPool rng;
  do {
    CryptoPP::SecByteBlock scratch(n.ByteCount()-1);
    // Random Block
    rng.GenerateBlock(scratch, scratch.size());
    r.Decode(scratch.BytePtr(), scratch.SizeInBytes());
  } while (!CryptoPP::RelativelyPrime(n, r));
  return r;
}

/**
 * @brief      Loads a RSA key from the specified file_name. Can be used for
 * both public and private RSA keys.
 *
 * @param      key        The CryptoPP RSA key instance
 * @param[in]  file_name  The file name
 */
void load_rsa_key(CryptoPP::RSAFunction& key, const std::string& file_name) {
  CryptoPP::ByteQueue byte_queue;
  CryptoPP::FileSource key_file(
      file_name.c_str(), true, new CryptoPP::Base64Decoder());
  key_file.TransferTo(byte_queue);
  byte_queue.MessageEnd();
  key.Load(byte_queue);
}

/**
 * @brief      Sets the symmetric key of a cipher given an input key.
 *
 * @param      cipher     The cipher. Currently assumes AES as the cipher.
 * @param[in]  input_key  The input key
 */
void set_symm_key(CryptoPP::SymmetricCipher& cipher, const Integer& input_key) {
  size_t input_key_size = input_key.MinEncodedSize();

  if (cipher.IsValidKeyLength(input_key_size)) {
    CryptoPP::SecByteBlock key(input_key_size);
    input_key.Encode(key.BytePtr(), input_key_size);
    cipher.SetKey(key, key.size());
  } else {
    byte input_key_byte[input_key_size];
    input_key.Encode(input_key_byte, input_key_size);

    // Take the SHA256 digest of input as symmetric key to transform it to key
    // of valid keylength for the cipher
    CryptoPP::SecByteBlock digest(CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::SHA256 sha256;
    sha256.CalculateDigest(digest.BytePtr(), input_key_byte, input_key_size);

    cipher.SetKey(digest, digest.size());
  }
}

/**
 * @brief      Encrypts file by chunks with the specified key. AES on ECB is
 *             used as the encryption algorithm. The output file will be named
 *             <file_name>.enc
 *
 * @param[in]  file_name  The file name
 * @param[in]  key        The key
 *
 * @return     The access token for the file.
 */
std::string encrypt_file_by_chunks(
    const std::string& file_name, const Integer& key) {
  CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes;
  set_symm_key(aes, key);

  // Use the key to encrypt the file every x bytes (chunk)
  // Use 1023 as CHUNK_SIZE to allow 1 byte padding (indicate endpoint of the
  // ciphertext)
  const unsigned int CHUNK_SIZE = 1023;
  char char_block[CHUNK_SIZE] = {'\0'};
  char token_buf[CHUNK_SIZE] = {'\0'};

  std::ifstream in_file(file_name);
  std::ofstream out_file(file_name + ".enc", std::ios::binary);
  in_file.read(char_block, sizeof(char_block));
  while(in_file.gcount() > 0) {
    std::string plain(char_block, in_file.gcount());
    std::string cipher;

    // The StreamTransformationFilter adds padding as required. ECB and CBC Mode
    // must be padded to the block size of the cipher.
    CryptoPP::StringSource sse(plain, true,
        new CryptoPP::StreamTransformationFilter(aes,
            new CryptoPP::StringSink(cipher)
        ) // StreamTransformationFilter
    ); // StringSource
       //
    out_file << cipher;

    for (int i = 0; i < CHUNK_SIZE; ++i) {
      token_buf[i] ^= cipher[i];
    }

    std::memset(char_block, 0, sizeof(char_block));
    in_file.read(char_block, sizeof(char_block));
  }
  in_file.close();
  out_file.close();

  std::string token;
  CryptoPP::StringSource sst(token_buf, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(token))
  );
  return token;
}

/**
 * @brief      Decrypts an encrypted file. The .enc suffix is implicit.
 *
 * @param[in]  file_name  The file name
 * @param[in]  key        The key
 */
void decrypt_file(const std::string& file_name, const Integer& key) {
  CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption aes;
  set_symm_key(aes, key);

  std::ofstream dec(file_name, std::ios::binary);
  std::ifstream enc(file_name + ".enc", std::ios::binary | std::ios::app);

  char buf[1024];
  enc.read(buf, sizeof(buf));
  while (enc.gcount() > 0) {
    std::string read(buf, enc.gcount());
    std::cout << "Read: " << enc.gcount() << std::endl;
    CryptoPP::StringSource ss(read, true,
      new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::FileSink(dec))
    );
    enc.read(buf, sizeof(buf));
  }
}

int main(int argc, char const *argv[]) {
  std::string file_name = "samples/1";
  if (argc > 1) {
    file_name = argv[1];
  }

  // generate_pub_pvt_key_pair();

  std::string digest = hash_file_stream(file_name);

  #ifdef DEBUG
  CryptoPP::StringSource(digest, true,
      new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
  std::cout << std::endl;
  #endif

  // Load (e,n)
  RSA::PublicKey pubkey;
  load_rsa_key(pubkey, "pubkey.txt");

  Integer m((byte const*)digest.data(), 32);
  Integer e = pubkey.GetPublicExponent();
  Integer n = pubkey.GetModulus();
  Integer r = generate_r(n);
  #ifdef DEBUG
  std::cout << "e: " << e << std::endl;
  std::cout << "n: " << n << std::endl;
  std::cout << "r: " << n << std::endl;
  std::cout << "m: " << m << std::endl;
  #endif

  CryptoPP::ModularArithmetic modn(n);

  Integer res = modn.Exponentiate(r, e);
  DEBUG_LOG("r^e mod n = ");
  DEBUG_LOG(res);

  res = modn.Multiply(m, res);
  DEBUG_LOG("m.r^e mod n = ");
  DEBUG_LOG(res);

  // Send over

  // ================================
  // Simulate P signing
  // ================================

  // Load (d)
  RSA::PrivateKey pvtkey;
  load_rsa_key(pvtkey, "privkey.txt");

  Integer d = pvtkey.GetPrivateExponent();
  #ifdef DEBUG
  assert(e == pvtkey.GetPublicExponent());
  assert(n == pvtkey.GetModulus());
  #endif

  Integer hdr = modn.Exponentiate(res, d);
  DEBUG_LOG("m'^d mod n = ");
  DEBUG_LOG(hdr);

  Integer hd_temp = modn.Exponentiate(m, d);

  // Receive digest^d
  Integer hd = modn.Divide(hdr, r);

  // Check if we get back the real digest
  Integer should_be_m = modn.Exponentiate(hd, e);
  #ifdef DEBUG
  assert(hd == hd_temp);
  assert(m == should_be_m);
  std::cout << "Size of h^d: " << hd.BitCount() << std::endl;
  std::cout << "MinEncodedSize: " << hd.MinEncodedSize() << std::endl;
  std::cout << "Byte count: " << hd.ByteCount() << std::endl;
  #endif

  // Encrypt file by block (size?)
  std::string token = encrypt_file_by_chunks(file_name, hd);
  // decrypt_file(file_name, hd);

  // Send over encrypted file.

  DEBUG_LOG("Reached the end. So most probably works as expected.");
  return 0;
}

#endif // _CLIENT_H_
