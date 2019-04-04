#include <fstream>
#include <memory>
#include <cassert>
#include <cstring>

#include "base64.hpp"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}

int main() {
    ERR_load_CRYPTO_strings();
    int rc;

    unsigned char key[32u];
    {
        auto stream = std::make_unique< std::ifstream >( "key.bin" );
        assert( stream->is_open() );

        const std::string keyDecoded = base64::decode( { std::istreambuf_iterator< char >( *stream ), {} } );
        for ( unsigned i = 0; i < 32u; i++ )
            key[i] = keyDecoded[i];
    }

    std::string input;
    {
        auto stream = std::make_unique< std::ifstream >( "provision_encrypted" );
        assert( stream->is_open() );

        const std::string inputEncoded = { std::istreambuf_iterator< char >( *stream ), {} };
        input = base64::decode( inputEncoded );
    }

    if( input.size() <= 16 )
        throw std::runtime_error( "Bad string" );

    unsigned char iv[16u];
    std::memcpy( iv, input.data(), 16u * sizeof( unsigned char ) );

    int inputSize = input.size() - 16u;
    auto *inputData = new unsigned char[ inputSize + 17u ];
    {
        unsigned char* d1 = inputData;
        const char* d2 = input.data() + 16u;

        for ( int i = 0; i < inputSize; i++, d1++, d2++)
            *d1 = static_cast< unsigned char >( *d2 );

        for(; inputSize % 16u != 0u; inputSize++, d1++ )
            *d1 = 0u;

        *d1 = 0u;
    }

    // EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init( ctx );
    EVP_CIPHER_CTX_set_padding( ctx, 1 );

    rc = EVP_CipherInit_ex( ctx, EVP_aes_256_cbc(), nullptr, key, iv, 0 );
    assert( rc == 1 );

    assert( EVP_CIPHER_CTX_key_length( ctx ) == 32 );
    assert( EVP_CIPHER_CTX_iv_length( ctx ) == 16 );

    int cipherSize = inputSize;
    auto cipherData = new unsigned char[ cipherSize + 1u ];

    rc = EVP_CipherUpdate( ctx, cipherData, &cipherSize, inputData, inputSize );
    assert( rc == 1 );

    for ( auto cipherEnd = cipherData + cipherSize; *cipherEnd; cipherEnd++ )
        cipherSize++;

    {
        auto stream = std::make_unique< std::ofstream >( "provision_decrypted" );
        assert( stream->is_open() );

        const std::string output { cipherData, cipherData + cipherSize };
        ( *stream ) << output;
    }

    return 0;
}
