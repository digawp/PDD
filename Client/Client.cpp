#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
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

  std::string encoded_digest;

  CryptoPP::StringSource(digest, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded_digest)));

  return encoded_digest;
}

int main(int argc, char const *argv[]) {
  std::string file_name = "samples/1";
  if (argc > 1) {
      file_name = argv[1];
  }

  std::string hash = hash_fn(file_name);
  std::cout << hash << std::endl;
  return 0;
}

#endif // _CLIENT_H_
