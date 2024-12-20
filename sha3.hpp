/*
 * Copyright (C) 2019-2022, Xilinx, Inc.
 * Copyright (C) 2022-2023, Advanced Micro Devices, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @file sha3.hpp
 * @brief header file for SHA-3 related functions, including permutation-based hash and extendable-ouput functions.
 * This file is part of Vitis Security Library.
 *
 * @detail KECCAK_f is the permutation function which is equivalent to KECCAK-p[1600,24] as defined in the standard.
 * sha3Digest is the main digest part which is responsible for absorbing the input 64-bit message stream into 1600-bit
 * blocks,
 * and squeezing the specific bits of the state array which calculated by the KECCAK_f as the digest according to the
 * suffix of the algorithm.
 * shakeXOF is the extendable-ouput function, the division for message block length can be optimized furtherly using
 * magic number decomposition method.
 *
 */
// 64-bit rotate left
#define ROL(v, n) (((v) << (n)) | ((v) >> (64-(n))))
#include <queue>
#include <boost/multiprecision/cpp_int.hpp>
using namespace boost::multiprecision;
using namespace std;

namespace xfsw {
namespace security {
namespace internal {

// @brief 1600-bit Processing block
struct blockType {
    uint64_t M[25];
    blockType() {}
};

/**
 *
 * @brief The implementation of KECCAK-f permutation function.
 *
 * The algorithm reference is : "SHA-3 Standard : Permutation-Based Hash and Extendable-Output Functions".
 * The implementation is modified for better performance.
 *
 * @param stateArray The 5*5*64 state array defined in standard.
 *
 */

static void KECCAK_f(
    // in-out
    uint64_t stateArray[25]) {
    // round index for iota
    const uint64_t roundIndex[24] = 
        {0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

    for (int rnd = 0; rnd < 24; rnd++) {
        // 1st step theta
        uint64_t rowReg[5];
        for (int i = 0; i < 5; i++) {
            rowReg[i] = stateArray[i] ^ stateArray[i + 5] ^ stateArray[i + 10] ^ stateArray[i + 15] ^ stateArray[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            uint64_t tmp = rowReg[(i + 4) % 5] ^ ROL(rowReg[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                stateArray[i + j] ^= tmp;
            }
        }
        // std::cout << "first step:" << std::endl;
        // for (int i = 0; i < 25; i++) {
        //     std::cout << "stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray[i] << std::endl;
        // }

        // 2nd step rho, and 3rd step pi
        uint64_t tmpStateArray[24];
        {
            tmpStateArray[0] = ROL(stateArray[1], 1);
            tmpStateArray[1] = ROL(stateArray[10], 3);
            tmpStateArray[2] = ROL(stateArray[7], 6);
            tmpStateArray[3] = ROL(stateArray[11], 10);
            tmpStateArray[4] = ROL(stateArray[17], 15);
            tmpStateArray[5] = ROL(stateArray[18], 21);
            tmpStateArray[6] = ROL(stateArray[3], 28);
            tmpStateArray[7] = ROL(stateArray[5], 36);
            tmpStateArray[8] = ROL(stateArray[16], 45);
            tmpStateArray[9] = ROL(stateArray[8], 55);
            tmpStateArray[10] = ROL(stateArray[21], 2);
            tmpStateArray[11] = ROL(stateArray[24], 14);
            tmpStateArray[12] = ROL(stateArray[4], 27);
            tmpStateArray[13] = ROL(stateArray[15], 41);
            tmpStateArray[14] = ROL(stateArray[23], 56);
            tmpStateArray[15] = ROL(stateArray[19], 8);
            tmpStateArray[16] = ROL(stateArray[13], 25);
            tmpStateArray[17] = ROL(stateArray[12], 43);
            tmpStateArray[18] = ROL(stateArray[2], 62);
            tmpStateArray[19] = ROL(stateArray[20], 18);
            tmpStateArray[20] = ROL(stateArray[14], 39);
            tmpStateArray[21] = ROL(stateArray[22], 61);
            tmpStateArray[22] = ROL(stateArray[9], 20);
            tmpStateArray[23] = ROL(stateArray[6], 44);
        }
        // std::cout << "second step:" << std::endl;
        // for (int i = 0; i < 24; i++) {
        //     std::cout << "stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << tmpStateArray[i] << std::endl;
        // }

        {
            stateArray[10] = tmpStateArray[0];
            stateArray[7] = tmpStateArray[1];
            stateArray[11] = tmpStateArray[2];
            stateArray[17] = tmpStateArray[3];
            stateArray[18] = tmpStateArray[4];
            stateArray[3] = tmpStateArray[5];
            stateArray[5] = tmpStateArray[6];
            stateArray[16] = tmpStateArray[7];
            stateArray[8] = tmpStateArray[8];
            stateArray[21] = tmpStateArray[9];
            stateArray[24] = tmpStateArray[10];
            stateArray[4] = tmpStateArray[11];
            stateArray[15] = tmpStateArray[12];
            stateArray[23] = tmpStateArray[13];
            stateArray[19] = tmpStateArray[14];
            stateArray[13] = tmpStateArray[15];
            stateArray[12] = tmpStateArray[16];
            stateArray[2] = tmpStateArray[17];
            stateArray[20] = tmpStateArray[18];
            stateArray[14] = tmpStateArray[19];
            stateArray[22] = tmpStateArray[20];
            stateArray[9] = tmpStateArray[21];
            stateArray[6] = tmpStateArray[22];
            stateArray[1] = tmpStateArray[23];
        }
        // std::cout << "third step:" << std::endl;
        // for (int i = 0; i < 24; i++) {
        //     std::cout << "stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray[i] << std::endl;
        // }

        // 4th step chi
        for (int j = 0; j < 25; j += 5) {
            uint64_t stateReg[5];
            for (int i = 0; i < 5; i++) {
                stateReg[i] = stateArray[j + i];
            }
            for (int i = 0; i < 5; i++) {
                stateArray[j + i] ^= (~stateReg[(i + 1) % 5]) & stateReg[(i + 2) % 5];
            }
        }
        // std::cout << "fourth step:" << std::endl;
        // for (int i = 0; i < 25; i++) {
        //     std::cout << "stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray[i] << std::endl;
        // }

        // 5th step iota
        stateArray[0] ^= roundIndex[rnd];
        // std::cout << "fifth step:" << std::endl;
        // std::cout << "stateArray[" << 0 << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray[0] << std::endl;
    }

} // end KECCAK_f

/**
 *
 * @brief This function performs the computation of SHA-3.
 *
 * The algorithm reference is : "SHA-3 Standard : Permutation-Based Hash and Extendable-Output Functions".
 * The implementation is modified for better performance.
 *
 * @tparam hashLen The width of the digest in byte, default value is 32 (SHA3-256).
 *
 * @param msgStrm The message being hashed.
 * @param msgLenStrm Message length in byte.
 * @param endMsgLenStrm The flag to signal end of input message stream.
 * @param digestStrm Output digest stream.
 * @param endDigestStrm End flag for output digest stream.
 *
 */

template <unsigned int hashLen = 32>
void sha3Digest(
    // inputs
    queue<uint64_t>& msgStrm,
    queue<uint128_t>& msgLenStrm,
    queue<bool>& endMsgLenStrm,
    // outputs
    queue<uint512_t>& digestStrm,
    queue<bool>& endDigestStrm) {
    // max data width in byte for 1 single block
    const int sizeR = 200 - (hashLen << 1);

    // number of message word for filling up 1 full block
    const int numMsgWord = sizeR >> 3;

    bool endFlag = endMsgLenStrm.front();
    endMsgLenStrm.pop();
    while (!endFlag) {
        // read message length in byte
        uint128_t msgLen = msgLenStrm.front();
        msgLenStrm.pop();

        // total number of blocks to digest
        uint128_t blkNumReg = msgLen / sizeR;
        uint128_t blkNum = blkNumReg + 1;

        // state array
        blockType stateArray;
        // std::cout << "stateArray reset:" << std::endl;
        for (int i = 0; i < 25; i++) {
            stateArray.M[i] = 0x0ULL;
            // std::cout << "stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray.M[i] << std::endl;
        }

        // number of bytes left
        uint128_t left = msgLen;
        // std::cout << "start processing:" << std::endl;
        for (uint128_t n = 0; n < blkNum; n++) {
            // still have full message block to handle
            if ((left >> 3) >= numMsgWord) {
                // generate 1 full message block
                for (int i = 0; i < numMsgWord; ++i) {
                    // XXX algorithm assumes little-endian
                    uint64_t msgReg = msgStrm.front();
                    // std::cout << std::setw(16) << std::setfill('0') << std::hex << msgReg << std::endl;
                    msgStrm.pop();
                    stateArray.M[i] ^= msgReg;
                    // std::cout << "update stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray.M[i] << std::endl;
                }
                // decrease number of bytes left by max data width in byte for 1 single block
                left -= sizeR;
                // left message words cannot make up a full message block
            } else {
                // cout << "entrou";
                // generate the last block
                for (int i = 0; i < numMsgWord; ++i) {
                    // still have full message words
                    if (i < (left >> 3)) {
                        // XXX algorithm assumes little-endian
                        uint64_t msgReg = msgStrm.front();
                        msgStrm.pop();
                        stateArray.M[i] ^= msgReg;
                    } else if (i == (left >> 3)) {
                        // xor 0x06 at the end of the message
                        uint8_t e = left & 0x7ULL;
                        if (e == 0) {
                            // contains no message byte
                            stateArray.M[i] ^= 0x0000000000000006ULL;
                        } else if (e == 1) {
                            // contains 1 message byte
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x00000000000000ffULL;
                            stateArray.M[i] ^= (msgReg | 0x0000000000000600ULL);
                        } else if (e == 2) {
                            // contains 2 message bytes
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x000000000000ffffULL;
                            stateArray.M[i] ^= (msgReg | 0x0000000000060000ULL);
                        } else if (e == 3) {
                            // contains 3 message bytes
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x0000000000ffffffULL;
                            stateArray.M[i] ^= (msgReg | 0x0000000006000000ULL);
                        } else if (e == 4) {
                            // contains 4 message bytes
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x00000000ffffffffULL;
                            stateArray.M[i] ^= (msgReg | 0x0000000600000000ULL);
                        } else if (e == 5) {
                            // contains 5 message bytes
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x000000ffffffffffULL;
                            stateArray.M[i] ^= (msgReg | 0x0000060000000000ULL);
                        } else if (e == 6) {
                            // contains 6 message bytes
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x0000ffffffffffffULL;
                            stateArray.M[i] ^= (msgReg | 0x0006000000000000ULL);
                        } else {
                            // contains 7 message bytes
                            // XXX algorithm assumes little-endian
                            uint64_t msgReg = msgStrm.front();
                            msgStrm.pop();
                            msgReg &= 0x00ffffffffffffffULL;
                            stateArray.M[i] ^= (msgReg | 0x0600000000000000ULL);
                        }
                    }
                    if (i == (numMsgWord - 1)) {
                        stateArray.M[i] ^= 0x8000000000000000ULL;
                    }
                }
            }
            // permutation
            KECCAK_f(stateArray.M);
        }

        // emit digest
        uint512_t digest = 0;
        for (int i = 7; i >= 0; i--) {
            // XXX algorithm assumes little-endian which is the same as HLS
            // thus no need to switch the byte order
            // std::cout << "digest = " << std::setw(128) << std::setfill('0') << std::hex << digest << std::endl;
            digest = (digest << 64) | stateArray.M[i];
            // std::cout << "stateArray[" << i << "] = " << std::setw(16) << std::setfill('0') << std::hex << stateArray.M[i] << std::endl;
            // std::cout << "update digest = " << std::setw(128) << std::setfill('0') << std::hex << digest << std::endl;
        }
        //  std::cout << "final digest = " << std::setw(128) << std::setfill('0') << std::hex << digest << std::endl;
        digestStrm.push(digest);
        endDigestStrm.push(false);

        //print
        // ostringstream oss;
        // oss.str("");
        // oss << hex;
        // for (int i = 63; i >= 0; i--) {
        //     oss << setw(2) << setfill('0') << (unsigned) (digest & 0xff);
        //     digest = digest >> 8;
        // }
        // std::cout << "digest = " << oss.str() << std::endl;

        // still have message to handle
        endFlag = endMsgLenStrm.front();
        endMsgLenStrm.pop();
    }
    endDigestStrm.push(true);
} // end sha3Digest
} // namespace internal

/**
 *
 * @brief Top function of SHA3-224.
 *
 * The algorithm reference is : "SHA-3 Standard : Permutation-Based Hash and Extendable-Output Functions".
 *
 * @param msgStrm The message being hashed.
 * @param msgLenStrm Message length in byte.
 * @param endMsgLenStrm The flag to signal end of input message stream.
 * @param digestStrm Output digest stream.
 * @param endDigestStrm End flag for output digest stream.
 *
 */

// static void sha3_224(
//     // inputs
//     queue<uint64_t >& msgStrm,
//     queue<uint128_t >& msgLenStrm,
//     queue<bool>& endMsgLenStrm,
//     // outputs
//     queue<ap_uint<224> >& digestStrm,
//     queue<bool>& endDigestStrm

//     ) {
//     internal::sha3Digest<28>(msgStrm, msgLenStrm, endMsgLenStrm, digestStrm, endDigestStrm);

// } // end sha3_224

/**
 *
 * @brief Top function of SHA3-256.
 *
 * The algorithm reference is : "SHA-3 Standard : Permutation-Based Hash and Extendable-Output Functions".
 *
 * @param msgStrm The message being hashed.
 * @param msgLenStrm Message length in byte.
 * @param endMsgLenStrm The flag to signal end of input message stream.
 * @param digestStrm Output digest stream.
 * @param endDigestStrm End flag for output digest stream.
 *
 */

// static void sha3_256(
//     // inputs
//     queue<uint64_t >& msgStrm,
//     queue<uint128_t >& msgLenStrm,
//     queue<bool>& endMsgLenStrm,
//     // outputs
//     queue<ap_uint<256> >& digestStrm,
//     queue<bool>& endDigestStrm

//     ) {
//     internal::sha3Digest<32>(msgStrm, msgLenStrm, endMsgLenStrm, digestStrm, endDigestStrm);

// } // end sha3_256

/**
 *
 * @brief Top function of SHA3-384.
 *
 * The algorithm reference is : "SHA-3 Standard : Permutation-Based Hash and Extendable-Output Functions".
 *
 * @param msgStrm The message being hashed.
 * @param msgLenStrm Message length in byte.
 * @param endMsgLenStrm The flag to signal end of input message stream.
 * @param digestStrm Output digest stream.
 * @param endDigestStrm End flag for output digest stream.
 *
 */

// static void sha3_384(
//     // inputs
//     queue<uint64_t >& msgStrm,
//     queue<uint128_t >& msgLenStrm,
//     queue<bool>& endMsgLenStrm,
//     // outputs
//     queue<ap_uint<384> >& digestStrm,
//     queue<bool>& endDigestStrm

//     ) {
//     internal::sha3Digest<48>(msgStrm, msgLenStrm, endMsgLenStrm, digestStrm, endDigestStrm);

// } // end sha3_384

/**
 *
 * @brief Top function of SHA3-512.
 *
 * The algorithm reference is : "SHA-3 Standard : Permutation-Based Hash and Extendable-Output Functions".
 *
 * @param msgStrm The message being hashed.
 * @param msgLenStrm Message length in byte.
 * @param endMsgLenStrm The flag to signal end of input message stream.
 * @param digestStrm Output digest stream.
 * @param endDigestStrm End flag for output digest stream.
 *
 */

static void sha3_512(
    // inputs
    queue<uint64_t>& msgStrm,
    queue<uint128_t>& msgLenStrm,
    queue<bool>& endMsgLenStrm,
    // outputs
    queue<uint512_t>& digestStrm,
    queue<bool>& endDigestStrm

    ) {
    internal::sha3Digest<64>(msgStrm, msgLenStrm, endMsgLenStrm, digestStrm, endDigestStrm);

} // end sha3_512

} // namespace security
} // namespace xf
