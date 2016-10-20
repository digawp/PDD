// Remove for production
#define DEBUG

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/osrng.h"
#include "cryptopp/sha.h"

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



Integer generate_r(Integer& n) {
  Integer r;
  do {
    /* code */
  } while (!CryptoPP::RelativelyPrime(n, r));
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

  // Read (e,n) from file

  // Generate r

  // Calculate digest * r^e

  // Send over

  // Receive digest^d

  // Encrypt file by block (size?)

  // Send over encrypted file.

  return 0;
}

#endif // _CLIENT_H_
