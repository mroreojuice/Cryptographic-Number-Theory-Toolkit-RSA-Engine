# Cryptographic Engine: Function Documentation

This document explains, in plain language, what each function in `rsa_number_theory.cpp` does, why it exists, and how it works under the hood.

---

## Class: `NumberTheory`

This class holds the low-level math operations that RSA encryption is built on. It has no custom constructor — you can create an instance of it the normal way, with no special setup.

### 1. `modularPower`

* **Signature:** `ull modularPower(ull base, ull exponent, ull mod)`
* **What it computes:** $(base^{exponent}) \bmod mod$

**Why this function exists:**
RSA constantly needs to raise huge numbers to huge powers, then take the remainder after dividing by another huge number. If you tried to compute the full power first (e.g. $base^{exponent}$) before taking the modulus, the number would explode to thousands of digits and overflow any normal data type almost instantly. This function avoids that by reducing the number modulo `mod` at every single step, so it never grows large.

**How it works — Binary Exponentiation (Square-and-Multiply):**
A naive approach would multiply `base` by itself `exponent` times in a loop, which takes $O(exponent)$ steps — way too slow when `exponent` has 300+ digits in real RSA. Instead, this function looks at the *binary representation* of the exponent and processes it bit by bit:

* If the current lowest bit of the exponent is `1` (checked via `exponent % 2 == 1`), it multiplies the running result by the current base (under the modulus).
* On every loop iteration, regardless of that bit, it squares the base ($base \to base^2 \to base^4 \to base^8 \dots$) and shifts the exponent right by one bit (integer-divides it by 2).

This turns the problem from linear time into logarithmic time: $O(\log(exponent))$. For a 1024-bit exponent, that's roughly 1024 iterations instead of an astronomically large number.

**Overflow protection:**
When you square a 64-bit `unsigned long long`, the result can need up to 128 bits to represent *before* the modulus is applied. To prevent silent overflow/wraparound, the function temporarily casts the multiplication to `__int128`, performs the multiply-and-mod safely in that wider type, then casts back down to 64 bits.

---

### 2. `extendedGCD`

* **Signature:** `vector<ll> extendedGCD(ll a, ll b)`
* **What it computes:** The greatest common divisor of $a$ and $b$, *plus* two integers $x$ and $y$ that satisfy Bézout's Identity:

$$ax + by = \gcd(a, b)$$

**Why this function exists:**
Plain GCD only tells you *that* two numbers share a common factor. RSA key generation needs more: it needs to find an inverse value, and the only practical way to do that is to also recover the $x$ and $y$ coefficients along the way. That's exactly what the extended version of the Euclidean Algorithm provides.

**How it works:**
It recursively applies the identity $\gcd(a, b) = \gcd(b,\ a \bmod b)$, repeatedly trading the pair $(a, b)$ for the smaller pair $(b,\ a \bmod b)$, until $b$ reaches $0$. At that point the recursion bottoms out, since $\gcd(a, 0) = a$.

As the recursive calls return back up the stack, each level reconstructs its own $x$ and $y$ from the deeper level's results ($x_1, y_1$) using back-substitution:

$$x = y_1$$
$$y = x_1 - \left\lfloor \frac{a}{b} \right\rfloor \times y_1$$

**Return value:** A 3-element vector in the order `{gcd, x, y}`.

---

### 3. `modularInverse`

* **Signature:** `ll modularInverse(ll a, ll m)`
* **What it computes:** A value $d$ such that:

$$(a \times d) \bmod m = 1$$

In other words, $d$ acts like "1 divided by $a$" inside modular arithmetic — multiplying by $d$ undoes multiplying by $a$.

**Why this function exists:**
This is the function that actually produces the RSA *private key exponent*. The public key lets you scramble a message by raising it to a power; the private key needs to be the mathematical "undo" operation for that, and that undo operation is a modular inverse.

**How it works:**
1. Calls `extendedGCD(a, m)` to get back the coefficient $x$ that satisfies $a \cdot x + m \cdot y = \gcd(a, m)$.
2. That raw $x$ can come back negative (a normal outcome of the Euclidean algorithm), so it's mapped into the proper positive range $[0, m-1]$ using:

$$\text{inverse} = \left( (x \bmod m) + m \right) \bmod m$$

**Error handling:**
A modular inverse only exists when $a$ and $m$ share no common factors, i.e. $\gcd(a, m) = 1$. If `extendedGCD` reports a GCD other than 1, there is no valid inverse, so the function throws a `std::runtime_error` rather than returning a meaningless number.

---

### 4. `isPrime`

* **Signature:** `bool isPrime(ull n)`
* **What it does:** Decides whether a 64-bit number is prime or composite.

**Why this function exists:**
RSA security depends on starting with two genuinely prime numbers. Checking primality by trial division (testing every possible divisor) is far too slow for numbers hundreds of bits long, so this function uses a much faster probabilistic-but-effectively-certain test instead.

**How it works — Miller-Rabin Primality Test:**

1. **Factor out powers of 2:** It rewrites $n - 1$ as $d \times 2^s$, where $d$ is odd. (Every even number can be broken down this way.)
2. **Test "witnesses":** For a number to be prime, for any witness value $a$, one of these must hold:

$$a^d \equiv 1 \pmod n$$

or, for some $r$ where $0 \le r < s$:

$$a^{\,d \cdot 2^r} \equiv -1 \pmod n$$

   (Note: $-1 \pmod n$ is the same as $n - 1$.) If neither condition holds for a particular witness, $n$ is definitely composite.
3. **Fixed witness set:** Rather than testing random witnesses (as textbook Miller-Rabin does), this implementation always tests the same 12 fixed bases: `{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}`. This isn't a shortcut that sacrifices accuracy — it's actually been mathematically proven that **no composite number below $2^{64}$ can fool all 12 of these specific bases**. So for any 64-bit input, this test is 100% deterministic and correct, not just "probably right."

**Return value:** `false` the moment any witness proves `n` composite; `true` only if `n` survives every witness check.

---

### 5. `generateRandomPrime`

* **Signature:** `ull generateRandomPrime(int bits)`
* **What it does:** Produces a random prime number with a specific bit length.

**Why this function exists:**
RSA key generation needs two large, independent, randomly chosen prime numbers ($p$ and $q$). This function is the factory that produces each one.

**How it works:**
1. Uses `std::mt19937_64`, a high-quality 64-bit random number generator, seeded from `std::random_device` (which pulls entropy from the OS/hardware, not a predictable software clock).
2. Draws a random candidate number that falls between the lowest and highest values possible for the requested bit length (e.g., for 16 bits, somewhere between $2^{15}$ and $2^{16}-1$).
3. Applies two bitwise OR adjustments to the candidate:
   * `candidate | 1ULL` — forces the lowest bit to `1`, guaranteeing the number is odd (even numbers greater than 2 can never be prime, so there's no point testing them).
   * `candidate | low` — forces the highest bit to `1`, guaranteeing the number actually has the requested bit length rather than being too small.
4. Passes the candidate to `isPrime()`. If it fails the test, the candidate is discarded and a fresh one is drawn — repeating until a genuine prime is found.

---

## Class: `SimpleRSA`

This class sits on top of `NumberTheory` and turns the raw math into an actual usable encryption/decryption system.

### 1. `generateKeys`

* **Signature:** `void generateKeys(int primeBits)`
* **What it does:** Generates the matching public key $(n, e)$ and private key $(n, d)$.

**How it works, step by step:**

1. Generates two different large primes, $p$ and $q$, each via `generateRandomPrime(primeBits)` — and makes sure $p \neq q$.
2. Multiplies them to get the public modulus:

$$n = p \times q$$

3. Computes Euler's Totient, which counts how many numbers below $n$ share no common factor with $n$:

$$\phi(n) = (p - 1)(q - 1)$$

4. Picks the public exponent. The industry-standard choice is $e = 65537$, because it's large enough to be secure but still computationally cheap to use (it's $2^{16} + 1$, which has a very simple binary form). If $\phi$ is too small to safely use 65537, the code falls back to the smaller standard choice $e = 17$.
5. Confirms $e$ and $\phi$ share no common factors by checking that $\gcd(e, \phi) = 1$ via `extendedGCD`. If they do share a factor, $e$ is incremented by 2 (skipping even numbers, since $e$ must stay odd) and rechecked, repeating until a valid $e$ is found.
6. Computes the private exponent $d$ as the modular inverse of $e$:

$$d = e^{-1} \bmod \phi$$

— calculated by calling `modularInverse(e, phi)`.

After this runs, $(n, e)$ is the public key anyone can use to encrypt a message to you, and $(n, d)$ is the private key only you should have, used to decrypt it.

---

### 2. Key Getters

* **Signatures:**
  * `ull getPublicKeyN()`
  * `ull getPublicKeyE()`
  * `ull getPrivateKeyD()`

**What they do:**
Simple accessor methods that expose the internally generated $n$, $e$, and $d$ values — useful for printing keys, logging, testing, or handing the public key to someone else.

---

### 3. `encryptMessage`

* **Signature:** `vector<ull> encryptMessage(string message)`
* **What it does:** Turns a plaintext string into a list of encrypted numbers.

**How it works:**
1. Walks through the input string one character at a time.
2. Converts each character into its numeric ASCII value (cast as `unsigned char` to avoid sign-related issues).
3. Encrypts that single number $m$ using the public key formula:

$$c = m^e \bmod n$$

   — calculated via `modularPower`.
4. Pushes each resulting ciphertext number $c$ onto a `vector<ull>`, building up the full encrypted message one character at a time.

*Note: encrypting character-by-character like this is simple to understand but is not how real-world RSA implementations work in practice — they encrypt padded message blocks, not single bytes — so this design is best understood as an educational simplification.*

---

### 4. `decryptMessage`

* **Signature:** `string decryptMessage(vector<ull> cipherText)`
* **What it does:** Reverses the encryption process, turning the ciphertext numbers back into the original text.

**How it works:**
1. Walks through each number in the ciphertext vector.
2. Applies the private key formula to recover the original number:

$$m = c^d \bmod n$$

   — again via `modularPower`, but using the private exponent $d$ instead of $e$.
3. Casts the recovered number $m$ back into a `char`.
4. Appends each recovered character onto a string, which — once every block has been processed — is the fully restored original message.

---

## How the Pieces Fit Together

```
generateRandomPrime  ──┐
                        ├──> generateKeys ──> (n, e) public key
isPrime  ───────────────┘                ──> (n, d) private key
                                               │
extendedGCD ──> modularInverse ───────────────┘

encryptMessage  --(uses modularPower with e)--> ciphertext
decryptMessage  --(uses modularPower with d)--> plaintext
```

In short: the `NumberTheory` class provides the raw mathematical tools (fast modular exponentiation, GCD, primality testing, prime generation), and `SimpleRSA` wires those tools together into the actual key-generation, encryption, and decryption workflow.
