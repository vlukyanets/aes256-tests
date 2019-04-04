#include <fstream>
#include <memory>
#include <cassert>
#include <cstring>
#include <random>

#include "base64.hpp"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
}

void generateBytes( unsigned char* bytes, std::size_t len ) {
    std::random_device rd;
    std::uniform_int_distribution< unsigned char > dist( 0x00, 0xFF );

    for( int i = 0; i < len; i++ )
        bytes[i] = dist(rd);
}

int main() {
    int rc;

    unsigned char iv[16u];
    generateBytes( iv, 16u );

    unsigned char key[32u];
    {
        auto stream = std::make_unique< std::ifstream >( "key.bin" );
        assert( stream->is_open() );

        const std::string keyDecoded = base64::decode( { std::istreambuf_iterator< char >( *stream ), {} } );
        for ( unsigned i = 0u; i < 32u; i++ )
            key[i] = keyDecoded[i];
    }

    std::string input;
    {
        auto stream = std::make_unique< std::ifstream >( "provision.json" );
        assert( stream->is_open() );

        input = { std::istreambuf_iterator< char >( *stream ), {} };
    }

    int inputSize = input.size();
    auto *inputData = new unsigned char[ inputSize + 17u ];
    {
        unsigned char* d1 = inputData;
        const char* d2 = input.data();

        for( int i = 0; i < inputSize; i++, d1++, d2++ )
            *d1 = static_cast< unsigned char >( *d2 );

        for(; inputSize % 16u != 0u; inputSize++, d1++ )
            *d1 = 0u;

        *d1 = 0u;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init( ctx );
    EVP_CIPHER_CTX_set_padding( ctx, 1 );

    rc = EVP_CipherInit_ex( ctx, EVP_aes_256_cbc(), nullptr, key, iv, 1 );
    assert( rc == 1 );

    assert( EVP_CIPHER_CTX_key_length( ctx ) == 32 );
    assert( EVP_CIPHER_CTX_iv_length( ctx ) == 16 );

    int cipherSize = 16u + inputSize + 16u;
    auto cipherData = new unsigned char[ cipherSize + 1u ];

    std::memcpy( cipherData, iv, 16u * sizeof( unsigned char ) );

    rc = EVP_CipherUpdate( ctx, cipherData + 16u, &cipherSize, inputData, inputSize );
    assert( rc == 1 );

    int cipherSizeFinal = 0;
    rc = EVP_CipherFinal_ex( ctx, cipherData + 16u + cipherSize, &cipherSizeFinal );
    assert( rc == 1 );

    {
        auto stream = std::make_unique< std::ofstream >( "provision_encrypted" );
        assert( stream->is_open() );

        const std::string cipherDataStrBase64 = base64::encode( cipherData, 16u + cipherSize + cipherSizeFinal );
        ( *stream ) << cipherDataStrBase64;
    }

    return 0;
}
