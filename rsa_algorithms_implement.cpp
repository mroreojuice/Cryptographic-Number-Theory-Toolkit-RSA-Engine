
// Cryptographic Number Theory Toolkit & Tiny RSA Engine (C++)
// Primitives: Binary Modular Exponentiation, Extended GCD, Miller-Rabin Test


#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <stdexcept>

using namespace std;

typedef unsigned long long ull;
typedef long long ll;


class NumberTheory {
public:

    /*   
     * Computes (base^exponent) % mod using binary exponentiation.
     * Time Complexity: O(log(exponent))
     */
    ull modularPower(ull base, ull exponent, ull mod) {
        if (mod == 1) return 0;

        ull result = 1;
        base = base % mod;

        while (exponent > 0) {
            // If current bit is set, multiply base to result
            if (exponent % 2 == 1) {
                result = (ull)((__int128)result * base % mod);
            }
            // Bit shift: square base and halve exponent
            base = (ull)((__int128)base * base % mod);
            exponent = exponent / 2;
        }
        return result;
    }

    /*
     * Computes extended GCD such that: ax + by = gcd(a, b)
     * Used for isolating modular multiplicative inverse coefficients.
     * returns {gcd,x,y} 
     */
    vector<ll> extendedGCD(ll a, ll b) {
        if (b == 0) {
            return {a, 1, 0}; // Base case: ax + 0y = a -> x=1, y=0
        }

        vector<ll> smallerAnswer = extendedGCD(b, a % b);

        ll gcd = smallerAnswer[0];
        ll x1  = smallerAnswer[1];
        ll y1  = smallerAnswer[2];

        // Inductive step update formulas
        ll x = y1;
        ll y = x1 - (a / b) * y1;

        return {gcd, x, y};
    }

    /*
     * Computes modular multiplicative inverse: (a * d) % m == 1
     * throws runtime_error if parameters are not co-prime (gcd != 1)
     */
    ll modularInverse(ll a, ll m) {
        vector<ll> result = extendedGCD(a, m);
        ll gcd = result[0];
        ll x = result[1];

        if (gcd != 1) {
            throw runtime_error("Modular inverse does not exist (gcd != 1)");
        }

        // Adjust negative coefficients into bounded field [0, m-1]
        return (x % m + m) % m;
    }

    /*
     * Probabilistic check for primality using deterministic 64-bit bases.
     * Guaranteed 100% accurate for all inputs bounded by uint64_t limits.
     * if returned flase then number is guaranteed to be non prime
     * if true then it means it passed the test, there is a certain probability that the number is not prime
     */

    bool isPrime(ull n) {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        // Express factorization state n - 1 = d * 2^s where d is odd
        ull d = n - 1;
        int s = 0;
        while (d % 2 == 0) {
            d /= 2;
            s++;
        }

        // Deterministic witness base set for 64-bit integer space
        vector<ull> witnesses = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};

        for (ull a : witnesses) {
            if (a >= n) continue;

            ull x = modularPower(a, d, n);

            if (x == 1 || x == n - 1) continue;

            bool passedRound = false;
            for (int r = 0; r < s - 1; r++) {
                x = (ull)((__int128)x * x % n);
                if (x == n - 1) {
                    passedRound = true;
                    break;
                }
            }

            if (!passedRound) return false; // Composite confirmation
        }

        return true; // Prime confirmation
    }

    /**
     * Samples a random prime coordinate constrained within requested bit limits.
     */
    ull generateRandomPrime(int bits) {
        ull low = 1ULL << (bits - 1);
        ull high = (1ULL << bits) - 1;

        random_device rd;
        mt19937_64 generator(rd());
        uniform_int_distribution<ull> distribution(low, high);

        while (true) {
            ull candidate = distribution(generator);
            candidate |= 1ULL; // Enforce odd numbers
            candidate |= low;  // Prevent truncation beneath bit ceiling

            if (isPrime(candidate)) {
                return candidate;
            }
        }
    }
};

/**
 * Illustrative object handling key-generation, block encryption, and decryption steps.
 */
class SimpleRSA {
private:
    ull n; // Public Modulus
    ull e; // Public Exponent
    ull d; // Private Decryption Exponent
    NumberTheory nt;

public:
    /**
     * Allocates public/private algebraic components using input bit thresholds.
     */
    void generateKeys(int primeBits) {
        ull p = nt.generateRandomPrime(primeBits);
        ull q = nt.generateRandomPrime(primeBits);

        while (q == p) {
            q = nt.generateRandomPrime(primeBits);
        }

        n = p * q;
        ull phi = (p - 1) * (q - 1);

        e = 65537; // Standard verification exponent choice
        if (e >= phi) {
            e = 17;
        }

        // Ensure public exponent is coprime to Euler's totient metric
        while (nt.extendedGCD((ll)e, (ll)phi)[0] != 1) {
            e += 2;
        }

        d = (ull)nt.modularInverse((ll)e, (ll)phi);
    }

    ull getPublicKeyN() { return n; }
    ull getPublicKeyE() { return e; }
    ull getPrivateKeyD() { return d; }

    /**
     * Evaluates c = (m^e) % n sequence block-by-block across character vectors.
     */
    vector<ull> encryptMessage(string message) {
        vector<ull> cipherText;
        for (char ch : message) {
            ull asciiValue = (ull)(unsigned char)ch;
            cipherText.push_back(nt.modularPower(asciiValue, e, n));
        }
        return cipherText;
    }

    /**
     * Restores m = (c^d) % n sequence block-by-block to recover source plaintext string.
     */
    string decryptMessage(vector<ull> cipherText) {
        string originalMessage = "";
        for (ull c : cipherText) {
            originalMessage += (char)nt.modularPower(c, d, n);
        }
        return originalMessage;
    }
};

int main() {
    NumberTheory nt;

    // --- Primitive Executions Diagnostics ---
    cout << "===== Math Primitive Performance Verification =====" << endl;
    vector<ull> testNumbers = {2, 17, 561, 97, 1000000007ULL};
    for (ull num : testNumbers) {
        cout << "Primality of " << num << " -> " << (nt.isPrime(num) ? "PRIME" : "COMPOSITE") << endl;
    }
    cout << endl;

    ll a = 17, m = 3120;
    cout << "Modular inverse of " << a << " mod " << m << " = " << nt.modularInverse(a, m) << endl;
    cout << endl;

    // --- RSA Pipeline Testing ---
    cout << "===== RSA Cryptosystem Lifecycle Engine =====" << endl;
    SimpleRSA rsa;
    rsa.generateKeys(16); // 16-bit primitives used for development evaluation

    cout << "Public Param Pair (n, e)  : (" << rsa.getPublicKeyN() << ", " << rsa.getPublicKeyE() << ")" << endl;
    cout << "Private Param Pair (n, d) : (" << rsa.getPublicKeyN() << ", " << rsa.getPrivateKeyD() << ")" << endl;

    string message = "Hello RSA!";
    cout << "\nPlaintext Target: " << message << endl;

    vector<ull> encrypted = rsa.encryptMessage(message);
    cout << "Ciphertext Stream: ";
    for (ull val : encrypted) cout << val << " ";
    cout << endl;

    string decrypted = rsa.decryptMessage(encrypted);
    cout << "Decrypted Result : " << decrypted << endl;

    if (decrypted == message) {
        cout << "\n[STATUS: LIFECYCLE PARITY CHECK PASSED]" << endl;
    } else {
        cout << "\n[STATUS: ALGEBRAIC PARITY ERROR]" << endl;
    }

    return 0;
}