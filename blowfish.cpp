//
// Blowfish C++ implementation (simplified, fully commented)
// CC0 - Public Domain
//

#include "blowfish.h"   // Class declaration (not shown here)
#include <cstring>      // For memcpy
#include <algorithm>    // For std::swap

// Detect system endianness (default to little endian if unknown)
#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#define __LITTLE_ENDIAN__
#endif

// Anonymous namespace to keep helper structures private to this file
namespace {

//---------------------------------------------
// 32-bit converter (used for byte manipulation)
//---------------------------------------------
union Converter32
{
    uint32_t bit_32;  // Full 32-bit integer

    struct
    {
#ifdef __LITTLE_ENDIAN__
        uint8_t byte3; // Most significant byte
        uint8_t byte2;
        uint8_t byte1;
        uint8_t byte0; // Least significant byte
#else
        uint8_t byte0;
        uint8_t byte1;
        uint8_t byte2;
        uint8_t byte3;
#endif
    } bit_8; // Structure for accessing individual bytes
};

//---------------------------------------------
// Blowfish initial constants
// (actual tables omitted for brevity)
//---------------------------------------------

const uint32_t initial_pary[18] = {
    // Normally: 18 constants derived from the hexadecimal digits of π
};

const uint32_t initial_sbox[4][256] = {
    // Normally: 4 arrays of 256 32-bit constants (from π)
};

//---------------------------------------------
// Helper function: Greatest Common Divisor
//---------------------------------------------
int GCD(int larger, int smaller)
{
    int gcd = smaller;
    int gcd_prev = larger;
    int gcd_next;

    // Euclidean algorithm
    while ((gcd_next = gcd_prev % gcd) != 0)
    {
        gcd_prev = gcd;
        gcd = gcd_next;
    }

    return gcd;
}

} // end anonymous namespace


//-----------------------------------------------------------
// Function: Blowfish::SetKey
// Initializes the P-array and S-boxes using the given key.
//-----------------------------------------------------------
void Blowfish::SetKey(const unsigned char* key, int byte_length)
{
    // Step 1: Copy initial constants into member arrays
    std::memcpy(pary_, initial_pary, sizeof(initial_pary));
    std::memcpy(sbox_, initial_sbox, sizeof(initial_sbox));

    // Determine how many 32-bit elements in P-array and S-box combined
    static const int pary_length = sizeof(pary_) / sizeof(uint32_t);
    static const int sbox_length = sizeof(sbox_) / sizeof(uint32_t);

    // Step 2: Prepare a temporary buffer to hold 32-bit key blocks
    int buffer_length = byte_length / GCD(byte_length, sizeof(uint32_t));
    uint32_t* key_buffer = new uint32_t[buffer_length];

    // Step 3: Fill buffer with 32-bit words made from the key bytes
    for (int i = 0; i < buffer_length; ++i)
    {
        Converter32 converter;

        // Each word is made of 4 bytes, cycling through key as needed
        converter.bit_8.byte0 = key[(i * 4) % byte_length];
        converter.bit_8.byte1 = key[(i * 4 + 1) % byte_length];
        converter.bit_8.byte2 = key[(i * 4 + 2) % byte_length];
        converter.bit_8.byte3 = key[(i * 4 + 3) % byte_length];

        key_buffer[i] = converter.bit_32;
    }

    // Step 4: XOR key material into the P-array
    for (int i = 0; i < pary_length; ++i)
    {
        uint32_t key_uint32 = key_buffer[i % buffer_length];
        pary_[i] ^= key_uint32;
    }

    delete[] key_buffer; // Clean up temporary buffer

    // Step 5: Key expansion — encrypting zero blocks repeatedly
    uint32_t left  = 0x00000000;
    uint32_t right = 0x00000000;

    // Encrypt all 18 entries of P-array (9 pairs)
    for (int i = 0; i < (pary_length / 2); ++i)
    {
        EncryptBlock(&left, &right);

        // Replace with output of encryption
        pary_[i * 2]     = left;
        pary_[i * 2 + 1] = right;
    }

    // Continue the process for all 4 S-boxes (1024 entries total)
    for (int i = 0; i < (sbox_length / 2); ++i)
    {
        EncryptBlock(&left, &right);

        // Write results back into S-box array
        reinterpret_cast<uint32_t*>(sbox_)[i * 2]     = left;
        reinterpret_cast<uint32_t*>(sbox_)[i * 2 + 1] = right;
    }
}


//-----------------------------------------------------------
// Function: Blowfish::Encrypt
// Encrypts a buffer of data in-place (multiple of 8 bytes).
//-----------------------------------------------------------
void Blowfish::Encrypt(unsigned char* dst, const unsigned char* src, int byte_length) const
{
    // If dst and src are different, copy the input first
    if (dst != src)
    {
        std::memcpy(dst, src, byte_length);
    }

    // Process data 8 bytes (64 bits) at a time
    for (int i = 0; i < byte_length / sizeof(uint64_t); ++i)
    {
        uint32_t* left  = &reinterpret_cast<uint32_t*>(dst)[i * 2];
        uint32_t* right = &reinterpret_cast<uint32_t*>(dst)[i * 2 + 1];

        // Encrypt a single 64-bit block
        EncryptBlock(left, right);
    }
}


//-----------------------------------------------------------
// Function: Blowfish::Decrypt
// Decrypts a buffer of data in-place (multiple of 8 bytes).
//-----------------------------------------------------------
void Blowfish::Decrypt(unsigned char* dst, const unsigned char* src, int byte_length) const
{
    // Copy data if necessary
    if (dst != src)
    {
        std::memcpy(dst, src, byte_length);
    }

    // Process each 8-byte block
    for (int i = 0; i < byte_length / sizeof(uint64_t); ++i)
    {
        uint32_t* left  = &reinterpret_cast<uint32_t*>(dst)[i * 2];
        uint32_t* right = &reinterpret_cast<uint32_t*>(dst)[i * 2 + 1];

        // Decrypt the 64-bit block
        DecryptBlock(left, right);
    }
}


//-----------------------------------------------------------
// Function: Blowfish::EncryptBlock
// Encrypts one 64-bit block (two 32-bit halves).
//-----------------------------------------------------------
void Blowfish::EncryptBlock(uint32_t* left, uint32_t* right) const
{
    // Blowfish has 16 rounds
    for (int i = 0; i < 16; ++i)
    {
        *left  ^= pary_[i];       // XOR with P-array value
        *right ^= Feistel(*left); // Apply Feistel function and XOR with right half
        std::swap(*left, *right); // Swap halves
    }

    // Undo last swap
    std::swap(*left, *right);

    // Final XORs with last two P-array entries
    *right ^= pary_[16];
    *left  ^= pary_[17];
}


//-----------------------------------------------------------
// Function: Blowfish::DecryptBlock
// Decrypts one 64-bit block (reverse of EncryptBlock).
//-----------------------------------------------------------
void Blowfish::DecryptBlock(uint32_t* left, uint32_t* right) const
{
    // Reverse 16 rounds
    for (int i = 0; i < 16; ++i)
    {
        *left  ^= pary_[17 - i];  // Reverse order of P-array
        *right ^= Feistel(*left); // Apply Feistel function
        std::swap(*left, *right); // Swap halves
    }

    // Undo last swap
    std::swap(*left, *right);

    // Final XORs (reverse order)
    *right ^= pary_[1];
    *left  ^= pary_[0];
}


//-----------------------------------------------------------
// Function: Blowfish::Feistel
// Core non-linear transformation function.
//-----------------------------------------------------------
uint32_t Blowfish::Feistel(uint32_t value) const
{
    // Split 32-bit input into four bytes
    Converter32 converter;
    converter.bit_32 = value;

    uint8_t a = converter.bit_8.byte0;
    uint8_t b = converter.bit_8.byte1;
    uint8_t c = converter.bit_8.byte2;
    uint8_t d = converter.bit_8.byte3;

    // Perform Blowfish F function:
    // F(x) = ((S1[a] + S2[b]) XOR S3[c]) + S4[d]
    return ((sbox_[0][a] + sbox_[1][b]) ^ sbox_[2][c]) + sbox_[3][d];
}
