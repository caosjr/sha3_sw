#define NUMBER_OF_BYTES 8
#define BLOCK_SIZE 9
#define NUMBER_OF_BLOCKS 100
#define ITERATIONS 100000
#define NUMBER_OF_TESTS (BLOCK_SIZE * NUMBER_OF_BLOCKS) * ITERATIONS

#include "sha3.hpp"
#include <iostream>
#include <chrono>
using namespace std;

// print hash value
std::string hash2str(uint512_t h, int len) {
    ostringstream oss;
    string retstr;

    // check output
    oss.str("");
    oss << hex;
    for (int i = 63; i >= 0; i--) {
        oss << setw(2) << setfill('0') << (unsigned) (h & 0xff);
        h = h >> 8;
    }
    retstr = oss.str();
    return retstr;
}

int main(int argc,  char * const argv[]) {
	queue<uint64_t>  msgStream;
    queue<uint128_t> msgLenStream;
    queue<bool>      endMsgStream;
    queue<uint512_t> digestStream;
    queue<bool>      endDigestStream;
    uint64_t msg = 0;

	for (int i = 0; i < NUMBER_OF_TESTS; i++) {
        msgStream.push(msg);
        msg++;
	}

    for (int i = 0; i < ITERATIONS; i++){
        msgLenStream.push((uint128_t)(BLOCK_SIZE * NUMBER_OF_BLOCKS * 8));
        endMsgStream.push(false);
    }
    endMsgStream.push(true);
    
    auto begin = std::chrono::high_resolution_clock::now();
    xfsw::security::sha3_512(msgStream, msgLenStream, endMsgStream, digestStream, endDigestStream);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-begin).count();
    std::cout << duration << "ns total, average : " << duration / ITERATIONS << "ns." << std::endl;

    uint512_t hashOut = 0;
    
    std::cout << "Digests: " << std::endl;
    while(!digestStream.empty()) {
        hashOut = digestStream.front();
        // std::cout << "Digest " << std::hex << hash2str(hashOut, 64) << std::endl;
        // std::cout << std::setw(128) << std::setfill('0') << std::hex << hashOut << std::endl;
        digestStream.pop();
    }

    while (!endDigestStream.empty()){
        endDigestStream.pop();
    }

	return 0;
}