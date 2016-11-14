// Remove for production
#define DEBUG

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>

#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/secblock.h"

using CryptoPP::Integer;
using CryptoPP::RSA;

std::string hash_fn(const std::string& file_name) {
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

  #ifdef DEBUG
  std::cout << "Bitcount: " << n.BitCount() << std::endl;
  #endif
  CryptoPP::AutoSeededRandomPool rng;
  do {
    CryptoPP::SecByteBlock scratch(n.ByteCount()-1);
    // Random Block
    rng.GenerateBlock(scratch, scratch.size());
    r.Decode(scratch.BytePtr(), scratch.SizeInBytes());
  } while (!CryptoPP::RelativelyPrime(n, r));
  return r;
}

int main(int argc, char const *argv[]) {
  std::string file_name = "samples/1";
  if (argc > 1) {
      file_name = argv[1];
  }

  std::string digest = hash_fn(file_name);

  #ifdef DEBUG
  CryptoPP::StringSource(digest, true,
      new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
  std::cout << std::endl;
  #endif

  // Load (e,n)
  RSA::PublicKey pubkey;
  {
    CryptoPP::FileSource pubkey_file(
        "pubkey.txt", true, new CryptoPP::Base64Decoder());
    CryptoPP::ByteQueue byte_queue;
    pubkey_file.TransferTo(byte_queue);
    pubkey.Load(byte_queue);
  }

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
  #ifdef DEBUG
  std::cout << "r^e mod n = " << res << std::endl;
  #endif

  res = modn.Multiply(m, res);
  #ifdef DEBUG
  std::cout << "m.r^e mod n = " << res << std::endl;
  #endif

  // Send over

  // ================================
  // Simulate P signing
  // ================================

  // Load (d)
  RSA::PrivateKey pvtkey;
  {
    CryptoPP::ByteQueue bytes;
    CryptoPP::FileSource file("privkey.txt", true, new CryptoPP::Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    pvtkey.Load(bytes);
  }

  Integer d = pvtkey.GetPrivateExponent();
  #ifdef DEBUG
  assert(e == pvtkey.GetPublicExponent());
  assert(n == pvtkey.GetModulus());
  #endif

  Integer hdr = modn.Exponentiate(res, d);
  #ifdef DEBUG
  std::cout << "m'^d mod n = " << hdr << std::endl;
  #endif
  Integer hd_temp = modn.Exponentiate(m, d);

  // Receive digest^d
  Integer hd = modn.Divide(hdr, r);

  // Check if we get back the real digest
  Integer should_be_m = modn.Exponentiate(hd, e);
  #ifdef DEBUG
  assert(hd == hd_temp);
  assert(m == should_be_m);
  #endif

  // Encrypt file by block (size?)

  // Send over encrypted file.

  return 0;
}

#endif // _CLIENT_H_
