#ifndef TRIVIUM_CYPHER_H
#define TRIVIUM_CYPHER_H

#include <vector>
#include <string>
#include <bitset>

class TriviumCypher {
private:
    std::bitset<93> registerA;
    std::bitset<84> registerB;
    std::bitset<111> registerC;
    std::vector<bool> keyStream;
    int warmupCycles = 4; // Based on Trivium documentation

public:
    TriviumCypher();
    TriviumCypher(const std::string& keyStr, const std::string& IV);
    void setUpKeyAndIV(std::string keyStr, std::string IV);
    bool getNextStreamBit();
    std::vector<bool> getStreamBitKey(int N);
    std::vector<bool> encrypt(const std::vector<bool>& plaintext);
    std::vector<bool> decrypt(const std::vector<bool>& ciphertext);
    void displayRegisters() const;
    void printKeyStream();
    std::vector<bool> stringToBitset(const std::string& text);
    std::string bitsetToString(const std::vector<bool>& bits);

private:
    bool getStateBit(int index) const;
    void warmupPhase();
};

#endif // TRIVIUM_CYPHER_H
