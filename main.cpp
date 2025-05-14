#include <iostream>
#include "TriviumCipher.h"

using namespace std;

int main() {
    TriviumCypher cipher;
    string keyStr, IV;
    bool cipherReady = false;
    bool running = true;

    vector<bool> lastEncryptedBits; // Store last encrypted message
    cout<<"Trivium Cipher by Oskars Stepanovs";
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
