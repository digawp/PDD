#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/pem.h"
#include "cryptopp/rsa.h"

using CryptoPP::Integer;

/**
 * @brief      Loads a RSA key from the specified file_name. Can be used for
 * both public and private RSA keys.
 *
 * @param      key        The CryptoPP RSA key instance
 * @param[in]  file_name  The file name
 */
void load_rsa_key(CryptoPP::RSA::PrivateKey& key, const std::string& file_name) {
  CryptoPP::FileSource key_file(file_name.c_str(), true);
  CryptoPP::PEM_Load(key_file, key);
}


bool blind_sign_digest(const char* blinded_digest, const int blinded_digest_len, char* return_val) {
    Integer digest_val((const byte*)blinded_digest, blinded_digest_len);

    std::cout << "Blinded digest received: " << std::endl << digest_val << std::endl;

    CryptoPP::RSA::PrivateKey key;
    load_rsa_key(key, "private_key.pem");

    CryptoPP::ModularArithmetic modn(key.GetModulus());
    // TODO: find out a better way to determine if return_val size is enough
    // Currently is just assume from size of RSA key
    Integer signed_digest = modn.Exponentiate(digest_val, key.GetPrivateExponent());

    signed_digest.Encode((byte*)return_val, signed_digest.MinEncodedSize());
    return true;
}
