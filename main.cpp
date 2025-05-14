#include <iostream>
#include <vector>
#include <string>
#include <bitset>
#include <algorithm> // for std::reverse

using namespace std;
class TriviumCypher{
    private:
        bitset<93> registerA;
        bitset<84> registerB;
        bitset<111> registerC;
        vector<bool> keyStream;
        int warmupCycles = 4; //shouldnt be changed, set based on Trivium documentation 
    public:
        // Default constructor (no parameters)
        TriviumCypher() {
            // std::cout << "Cipher object created without key and IV." << std::endl;
        }
        // Constructor that accepts key and IV strings
        TriviumCypher(const std::string& keyStr, const std::string& IV) {
            setUpKeyAndIV(keyStr, IV); // Initialize using the provided key and IV
        }
        void setUpKeyAndIV(string keyStr, string IV){
            try{
                // // Reverse the input string to match the bitset's right-to-left storage
                // reverse(keyStr.begin(), keyStr.end());
                // reverse(IV.begin(), IV.end());

                // Pad to match the size of target registers
                string paddedKey93 = string(registerA.size() - keyStr.length(), '0') + keyStr;
                string paddedIV84  = string(registerB.size() - IV.length(), '0') + IV;
                registerA.reset();
                registerB.reset();
                registerC.reset();
                registerA = bitset<93>(paddedKey93);
                registerB = bitset<84>(paddedIV84);
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


        bool getNextStreamBit(){
            bool t1=getStateBit(65)^getStateBit(92);
            bool t2=getStateBit(161)^getStateBit(176);
            bool t3=getStateBit(242)^getStateBit(287);
            bool keyStreamBit=t1^t2^t3;
            t1=t1^(getStateBit(90)&getStateBit(91))^getStateBit(170);
            t2=t2^(getStateBit(174)&getStateBit(175))^getStateBit(263);
            t3=t3^(getStateBit(285)&getStateBit(286))^getStateBit(68);

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
        vector<bool> getStreamBitKey(int N) {
            while (keyStream.size() < N) {
                getNextStreamBit();  // Generate and append bits until we've reached N
            }

            // Return the first N bits of the keyStream
            return std::vector<bool>(keyStream.begin(), keyStream.begin() + N);
        }

        // Encrypt or decrypt the text using XOR with the key stream
        vector<bool> encrypt(const vector<bool>& plaintext) {
            // Generate the key stream of the same length as the plaintext
            vector<bool> ciphertext;
            getStreamBitKey(plaintext.size());

            // XOR plaintext with the key stream to generate ciphertext
            for (size_t i = 0; i < plaintext.size(); ++i) {
                ciphertext.push_back(plaintext[i] ^ keyStream[i]);
            }

            return ciphertext;
        }
        
        vector<bool> decrypt(const std::vector<bool>& ciphertext) {
            // Decrypt the ciphertext in the same way as encryption (XOR with key stream)
            return encrypt(ciphertext);  // Decryption is the same as encryption
        }

        void displayRegisters() const {
            std::cout << "Register A: " << registerA << std::endl;
            std::cout << "Register B: " << registerB << std::endl;
            std::cout << "Register C: " << registerC << std::endl;
        }

        void printKeyStream() {
            std::cout << "Key Stream: ";
            for (bool bit : keyStream) {
                std::cout << bit;  // Print each bit (0 or 1)
            }
            std::cout << std::endl;
        }

        std::vector<bool> stringToBitset(const std::string& text) {
            std::vector<bool> bits;
            for (char c : text) {
                std::bitset<8> byte(c);  // Convert each character to an 8-bit representation
                for (int i = 7; i >= 0; --i) {  // Reverse order to match bitset's right-to-left indexing
                    bits.push_back(byte[i]);
                }
            }
            return bits;
        }

        std::string bitsetToString(const std::vector<bool>& bits) {
            std::string result;
            // Iterate over the bits in chunks of 8
            for (size_t i = 0; i < bits.size(); i += 8) {
                std::bitset<8> byte;
                // Set bits for the current byte
                for (int j = 0; j < 8 && i + j < bits.size(); ++j) {
                    byte[7 - j] = bits[i + j];  // Set bits in reverse order
                }
                // Convert the 8-bit bitset to a character
                char c = static_cast<char>(byte.to_ulong());
                result += c;  // Append the character to the result
            }
            return result;
        }
    private: 
        //helper function to get right register and index from state index tht combines all registers (value from 0 to 288)
        bool getStateBit(int index) const {
            if (index < 0 || index >= 288) {
                throw std::out_of_range("State index out of bounds (0–287).");
            }

            if (index < 93) {
                return registerA[index];  // Bits 0–92
            } else if (index < 93 + 84) {
                return registerB[index - 93];  // Bits 93–176
            } else {
                return registerC[index - 93 - 84];  // Bits 177–287
            }
        }

        void warmupPhase(){
            int internalStateCount=registerA.size()+registerB.size()+registerC.size();
            for (int i=0; i<warmupCycles*internalStateCount; i++){
                getNextStreamBit();
            }
            keyStream.clear();
        }
};
int main() {
    TriviumCypher cipher;
    string keyStr, IV;
    bool cipherReady = false;
    bool running = true;

    vector<bool> lastEncryptedBits; // Store last encrypted message

    while (running) {
        cout << "\n=== Trivium Cipher Menu ===\n";
        cout << "1. Set Key\n";
        cout << "2. Set Initialization Vector (IV)\n";
        cout << "3. Initialize Cipher (setUpKeyAndIV)\n";
        cout << "4. Generate Key Stream\n";
        cout << "5. Encrypt Message\n";
        cout << "6. Decrypt Last Encrypted Message\n";
        cout << "7. Print Key Stream\n";
        cout << "8. Exit\n";
        cout << "Choose an option: ";

        int choice;
        cin >> choice;
        cin.ignore();  // Ignore newline

        switch (choice) {
            case 1:
                cout << "Enter key (binary): ";
                getline(cin, keyStr);
                break;

            case 2:
                cout << "Enter init vector (binary): ";
                getline(cin, IV);
                break;

            case 3:
                try {
                    cipher.setUpKeyAndIV(keyStr, IV);
                    cipherReady = true;
                    cout << "Cipher initialized successfully.\n";
                } catch (const exception& e) {
                    cerr << "Error: " << e.what() << "\nMake sure key and IV are valid binary strings.\n";
                    cipherReady = false;
                }
                break;

            case 4: {
                if (!cipherReady) {
                    cout << "Please initialize the cipher first (option 3).\n";
                    break;
                }

                int streamLength;
                cout << "Enter key stream length to generate: ";
                cin >> streamLength;
                cin.ignore();

                cipher.getStreamBitKey(streamLength);
                cout << "Generated Key Stream:\n";
                cipher.printKeyStream();
                break;
            }

            case 5: {
                if (!cipherReady) {
                    cout << "Please initialize the cipher first (option 3).\n";
                    break;
                }

                string plainText;
                cout << "Enter plaintext to encrypt: ";
                getline(cin, plainText);

                vector<bool> plaintextBits = cipher.stringToBitset(plainText);
                lastEncryptedBits = cipher.encrypt(plaintextBits);  // Store encrypted bits
                string encryptedText = cipher.bitsetToString(lastEncryptedBits);
                cout << "Text (in bits): ";
                for (auto i : plaintextBits)
                    cout << i;
                cout << "\nEncyrpted text (in bits): ";
                for (auto i : lastEncryptedBits)
                    cout << i;
                cout << "\nEncrypted text: " << encryptedText << endl;
                break;
            }

            case 6: {
                if (!cipherReady) {
                    cout << "Please initialize the cipher first (option 3).\n";
                    break;
                }

                if (lastEncryptedBits.empty()) {
                    cout << "No encrypted message found. Please encrypt a message first (option 5).\n";
                    break;
                }

                vector<bool> decryptedBits = cipher.decrypt(lastEncryptedBits);
                string decryptedText = cipher.bitsetToString(decryptedBits);

                cout << "Decrypted text: " << decryptedText << endl;
                break;
            }
            case 7:
                if (!cipherReady) {
                    cout << "Please initialize the cipher first (option 3).\n";
                } else {
                    cipher.printKeyStream();
                }
                break;


            case 8:
                cout << "Exiting...\n";
                running = false;
                break;

            default:
                cout << "Invalid choice. Try again.\n";
        }
    }

    return 0;
}
