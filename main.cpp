#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

// SHA-256 Constants
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Right Rotate Operation
uint32_t rightrotate(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 Calculator Class
class SHA256 {
private:
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint64_t total_bytes = 0;
    
public:
    void update(const unsigned char* data, size_t length) {
        total_bytes += length;
        
        // Process each 64-byte block
        vector<unsigned char> buffer;
        buffer.reserve(64);
        
        for (size_t i = 0; i < length; ++i) {
            buffer.push_back(data[i]);
            
            if (buffer.size() == 64) {
                process_block(buffer.data());
                buffer.clear();
            }
        }
    }
    
    string finalize() {
        // Padding
        vector<unsigned char> padding;
        padding.push_back(0x80); // Append 1 followed by zeros
        
        // Calculate padding zeros
        size_t padding_bytes = 64 - ((total_bytes + 8) % 64);
        if (padding_bytes == 0) padding_bytes = 64;
        
        padding.resize(padding.size() + padding_bytes - 1, 0);
        
        // Append original message length in bits
        uint64_t bit_length = total_bytes * 8;
        for (int i = 7; i >= 0; --i) {
            padding.push_back((bit_length >> (i * 8)) & 0xFF);
        }
        
        // Process padding blocks
        update(padding.data(), padding.size());
        
        // Generate hash string
        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; ++i) {
            ss << setw(8) << h[i];
        }
        return ss.str();
    }
    
private:
    void process_block(const unsigned char* block) {
        // Initialize message schedule
        uint32_t w[64];
        
        // Break block into 16 32-bit words
        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | 
                   (block[i*4+2] << 8) | block[i*4+3];
        }
        
        // Extend the message
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        
        // Initialize working variables
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];
        
        // Main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // Add to current hash
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
};

string sha256(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Failed to open file: " << filename << endl;
        return "";
    }

    SHA256 sha;
    vector<char> buffer(1024 * 1024); // 1MB buffer

    while (file) {
        file.read(buffer.data(), buffer.size());
        streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            sha.update(reinterpret_cast<const unsigned char*>(buffer.data()), bytesRead);
        }
    }

    file.close();
    return sha.finalize();
}

int main() {
    cout << "Enter the path of the file to calculate SHA-256 hash: ";
    string filename;
    getline(cin, filename);

    string hash = sha256(filename);
    
    if (!hash.empty()) {
        cout << "File: " << filename << endl;
        cout << "SHA256: " << hash << endl;
    }
  else{
    cout << "Error!\n";
  }
  cin.ignore();
  hash.clear();
    return 0;
}
