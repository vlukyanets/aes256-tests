#include <fstream>
#include <memory>
#include <cassert>
#include <cstring>

#include "base64.hpp"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
}

int main() {
    int rc

    unsigned char key[32u];
    auto iv = (unsigned char*)"0123456789012345";

    {
        auto stream = std::make_unique< std::ifstream >( "key.bin" );
        assert( stream->is_open() );

        for( unsigned char& c : key )
            ( *stream ) >> c;
    }

    std::string input;
    {
        auto stream = std::make_unique< std::ifstream >( "input.txt" );
        assert( stream->is_open() );

        input = { std::istreambuf_iterator( *stream ), {} };
    }

    int inputSize = input.size();
    auto *inputData = new unsigned char[ inputSize + 1 ];
    {
        unsigned char* d1 = inputData;
        char* d2 = input.data();

        for (; *d2; d1++, d2++)
            *d1 = *d2;

        *d1 = 0;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    rc = EVP_CipherInit_ex( ctx, EVP_aes_256_cbc(), nullptr, key, iv, 1 );
    assert( rc == 1 );

    int cipherSize = inputSize + 16;
    auto cipherData = new unsigned char[ cipherSize + 1 ];

    rc = EVP_CipherUpdate( ctx, cipherData, &cipherSize, inputData, inputSize );
    assert( rc == 1 );

    

    return 0;
}
