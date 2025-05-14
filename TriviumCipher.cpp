#include "TriviumCipher.h"
#include <iostream>
#include <stdexcept>
#include <bitset>

TriviumCypher::TriviumCypher() {
    // std::cout << "Cipher object created without key and IV." << std::endl;
}

TriviumCypher::TriviumCypher(const std::string& keyStr, const std::string& IV) {
    setUpKeyAndIV(keyStr, IV); // Initialize using the provided key and IV
}

void TriviumCypher::setUpKeyAndIV(std::string keyStr, std::string IV) {
    try {
        // Pad to match the size of target registers
        std::string paddedKey93 = std::string(registerA.size() - keyStr.length(), '0') + keyStr;
        std::string paddedIV84  = std::string(registerB.size() - IV.length(), '0') + IV;
        registerA.reset();
        registerB.reset();
        registerC.reset();
        registerA = std::bitset<93>(paddedKey93);
        registerB = std::bitset<84>(paddedIV84);
        int regClastNlements=3;
        for (int i=0; i<regClastNlements; i++){
            registerC.set(registerC.size()-i-1);
        }
        warmupPhase();
    }
    catch (const std::exception& e) {
        throw;
    }
}

bool TriviumCypher::getNextStreamBit() {
    bool t1 = getStateBit(65) ^ getStateBit(92);
    bool t2 = getStateBit(161) ^ getStateBit(176);
    bool t3 = getStateBit(242) ^ getStateBit(287);
    bool keyStreamBit = t1 ^ t2 ^ t3;

    t1 = t1 ^ (getStateBit(90) & getStateBit(91)) ^ getStateBit(170);
    t2 = t2 ^ (getStateBit(174) & getStateBit(175)) ^ getStateBit(263);
    t3 = t3 ^ (getStateBit(285) & getStateBit(286)) ^ getStateBit(68);

    // Shift registers: insert new bits at front (index 0), discard oldest bits
    registerA <<= 1;
    registerA.set(0, t3); // left shift, so new bit goes at index 0

    registerB <<= 1;
    registerB.set(0, t1);

    registerC <<= 1;
    registerC.set(0, t2);

    keyStream.push_back(keyStreamBit);
    return keyStreamBit;
}

std::vector<bool> TriviumCypher::getStreamBitKey(int N) {
    while (keyStream.size() < N) {
        getNextStreamBit();  // Generate and append bits until we've reached N
    }

    // Return the first N bits of the keyStream
    return std::vector<bool>(keyStream.begin(), keyStream.begin() + N);
}

std::vector<bool> TriviumCypher::encrypt(const std::vector<bool>& plaintext) {
    // Generate the key stream of the same length as the plaintext
    std::vector<bool> ciphertext;
    getStreamBitKey(plaintext.size());

    // XOR plaintext with the key stream to generate ciphertext
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext.push_back(plaintext[i] ^ keyStream[i]);
    }

    return ciphertext;
}

std::vector<bool> TriviumCypher::decrypt(const std::vector<bool>& ciphertext) {
    // Decrypt the ciphertext in the same way as encryption (XOR with key stream)
    return encrypt(ciphertext);  // Decryption is the same as encryption
}

void TriviumCypher::displayRegisters() const {
    std::cout << "Register A: " << registerA << std::endl;
    std::cout << "Register B: " << registerB << std::endl;
    std::cout << "Register C: " << registerC << std::endl;
}

void TriviumCypher::printKeyStream() {
    std::cout << "Key Stream: ";
    for (bool bit : keyStream) {
        std::cout << bit;  // Print each bit (0 or 1)
    }
    std::cout << std::endl;
}

std::vector<bool> TriviumCypher::stringToBitset(const std::string& text) {
    std::vector<bool> bits;
    for (char c : text) {
        std::bitset<8> byte(c);  // Convert each character to an 8-bit representation
        for (int i = 7; i >= 0; --i) {  // Reverse order to match bitset's right-to-left indexing
            bits.push_back(byte[i]);
        }
    }
    return bits;
}

std::string TriviumCypher::bitsetToString(const std::vector<bool>& bits) {
    std::string result;
    for (size_t i = 0; i < bits.size(); i += 8) {
        std::bitset<8> byte;
        for (int j = 0; j < 8 && i + j < bits.size(); ++j) {
            byte[7 - j] = bits[i + j];  // Set bits in reverse order
        }
        char c = static_cast<char>(byte.to_ulong());
        result += c;
    }
    return result;
}

bool TriviumCypher::getStateBit(int index) const {
    if (index < 0 || index >= 288) {
        throw std::out_of_range("State index out of bounds (0–287).");
    }

    if (index < 93) {
        return registerA[index];
    } else if (index < 93 + 84) {
        return registerB[index - 93];
    } else {
        return registerC[index - 93 - 84];
    }
}

void TriviumCypher::warmupPhase() {
    int internalStateCount = registerA.size() + registerB.size() + registerC.size();
    for (int i = 0; i < warmupCycles * internalStateCount; i++) {
        getNextStreamBit();
    }
    keyStream.clear();
}
