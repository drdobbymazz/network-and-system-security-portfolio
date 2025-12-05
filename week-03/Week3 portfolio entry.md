# Week 3: Authentication and Access Control

**Module**: Networks and System Security  
**Student**: Zohaib Khokhar  
**Date**: December 2025  
**Topic**: Password Security, Hashing, and Two-Factor Authentication

---

## Overview

This week focused on building secure authentication systems from scratch. We explored why simple password checks aren't enough and implemented multiple layers of security including password hashing with bcrypt, salt and pepper techniques, and TOTP-based two-factor authentication. The workshop demonstrated the practical weaknesses of common authentication approaches and how to build robust defences.

---

## Section 1: Password Strength Analysis

### Understanding Password Strength

Password strength isn't just about length - it's about entropy, which measures unpredictability. A password like "password123" might be 11 characters long, but it has low entropy because it's predictable. Meanwhile, "T7$mK9@pLx" with 10 characters has much higher entropy due to character variety.

The key factors for strong passwords:
- **Length**: Most important factor. 8 characters is weak, 12 is decent, 16+ is excellent
- **Character variety**: Using lowercase, uppercase, numbers, and symbols increases the pool size
- **Avoiding common patterns**: Dictionary words, keyboard patterns (qwerty), repeated characters

### Implementation

I built a password strength analyzer that scores passwords based on:

```python
def analyze_password_strength(password):
    score = 0
    
    # Length scoring
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    
    # Character variety
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 1
    
    # Check against common passwords
    common_passwords = ['password', '123456', 'qwerty', 'admin']
    if password.lower() in common_passwords: score -= 3
```

### Entropy Calculation

Entropy measures how many guesses an attacker needs:

```
Approximate entropy = length × log2(pool_size)
```

For example:
- Lowercase only (26 characters): `12 × log2(26) = 56.4 bits`
- All character types (94 characters): `12 × log2(94) = 79.3 bits`

The difference is massive - the second password would require 2^23 (over 8 million) times more guesses to crack.

### Testing Results

Testing "Pass123" vs "MyP@ssw0rd2024":
- **Pass123**: Score 3/7 - Too short, no symbols, predictable pattern
- **MyP@ssw0rd2024**: Score 6/7 - Good length, all character types, substitution pattern

However, even the second one has issues - it uses common letter-to-number substitutions (@ for a, 0 for o) that sophisticated attackers expect. Truly random passwords or passphrases like "correct-horse-battery-staple" are more secure.

---

## Section 2: Password Hashing Methods

### Why Hash Instead of Store?

Storing plaintext passwords is a critical vulnerability. If your database is breached, every user account is immediately compromised. Hashing is a one-way function that transforms the password into a fixed-length string. Even if an attacker gets the hash, they can't reverse it to get the password.

### Comparing Hash Functions

**MD5 (Insecure)**
```python
import hashlib
hash_md5 = hashlib.md5(password.encode()).hexdigest()
# Output: 5f4dcc3b5aa765d61d8327deb882cf99
```

MD5 is dangerously fast - attackers can try billions of guesses per second on modern GPUs. It was never designed for passwords and has known collision vulnerabilities.

**SHA-256 (Also Insecure for Passwords)**
```python
hash_sha256 = hashlib.sha256(password.encode()).hexdigest()
# Output: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

SHA-256 is cryptographically secure for data integrity, but like MD5, it's far too fast for password storage. Speed is good for checksums but terrible for passwords.

**bcrypt (Secure)**
```python
import bcrypt
hash_bcrypt = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
# Output: $2b$12$N9qo8uLOickgx2ZMRZoMye7FVT6b5VjVdJKHEh4q9kL6YfJBCEZUq
```

bcrypt is intentionally slow and includes several security features:
- Built-in salt generation (automatic per-password randomness)
- Configurable work factor - can be increased as computers get faster
- Takes ~100-200ms per hash, making brute-force attacks impractical

### The Speed Problem

I tested hashing "password" 1000 times with each algorithm:
- **MD5**: ~0.003 seconds (instant)
- **SHA-256**: ~0.004 seconds (instant)
- **bcrypt**: ~4.2 seconds (noticeably slower)

This "slowness" is exactly what we want. An attacker with a stolen database has to spend that time for every single password guess. If they're trying 1 million common passwords against 1000 user accounts, that's:
- MD5: Minutes
- bcrypt: Years

### The bcrypt Hash Format

A bcrypt hash like `$2b$12$N9qo8u...` contains:
- `$2b$`: Algorithm version
- `12`: Work factor (2^12 = 4096 rounds)
- Next 22 chars: Salt (base64 encoded)
- Remaining: Actual hash

Everything needed for verification is in one string, which is why bcrypt verification works without storing the salt separately.

---

## Section 3: Salt and Pepper

### The Rainbow Table Problem

Without salt, identical passwords produce identical hashes. An attacker can precompute hashes for millions of common passwords (a "rainbow table") and instantly find matches in a stolen database.

### How Salt Works

A salt is random data added to each password before hashing. Every user gets a unique salt, so even if two users have "password123", their hashes are completely different.

```python
# Without salt - same password, same hash
hash1 = hashlib.sha256("mypassword".encode()).hexdigest()
hash2 = hashlib.sha256("mypassword".encode()).hexdigest()
# hash1 == hash2 (vulnerable to rainbow tables!)

# With salt - same password, different hashes
salt1 = os.urandom(16)
salt2 = os.urandom(16)
hash1 = hashlib.sha256(salt1 + "mypassword".encode()).hexdigest()
hash2 = hashlib.sha256(salt2 + "mypassword".encode()).hexdigest()
# hash1 != hash2 (rainbow tables useless)
```

The salt is stored in the database alongside the hash. It doesn't need to be secret - it just needs to be unique per user. This forces attackers to brute-force each password individually instead of cracking them all at once.

### Adding Pepper

A pepper is similar to salt but with key differences:
- **Salt**: Unique per user, stored in database
- **Pepper**: Same for all users, stored separately (environment variable, config file)

```python
PEPPER = "my_secret_system_pepper_2025"
hash_with_pepper = hashlib.sha256((password + PEPPER).encode()).hexdigest()
```

If an attacker steals the database, they get all the salts but not the pepper. Without the pepper, they can't verify their password guesses. This adds an extra layer - even if they compromise the database, they still need to compromise the application server or config files to get the pepper.

**Important**: Modern functions like bcrypt handle salting automatically. You generally don't need to manually add salt when using bcrypt, but understanding the principle is crucial.

---

## Section 4: Two-Factor Authentication (TOTP)

### Why 2FA Matters

Passwords can be stolen through phishing, data breaches, or keyloggers. Two-factor authentication (2FA) adds a second verification layer - typically "something you know" (password) plus "something you have" (your phone).

### How TOTP Works

TOTP (Time-based One-Time Password) generates temporary 6-digit codes that change every 30 seconds. It's based on a shared secret key and the current time:

```python
import pyotp

# Generate a secret key (done once during registration)
secret = pyotp.random_base32()

# Create TOTP instance
totp = pyotp.TOTP(secret)

# Generate current code
current_code = totp.now()
# Output: "483729" (changes every 30 seconds)

# Verify a code
is_valid = totp.verify(user_entered_code)
```

The clever part is that both the server and your authenticator app independently generate the same code at the same time using the shared secret and synchronized clocks. No internet connection needed after initial setup.

### Implementation

Setting up TOTP involves:

1. **Generate secret key** for the user
2. **Create QR code** containing the provisioning URI
3. **User scans QR code** with authenticator app (Google Authenticator, Authy, etc.)
4. **App generates codes** every 30 seconds
5. **Server verifies codes** during login

```python
# Create provisioning URI
uri = totp.provisioning_uri(
    name="user@example.com",
    issuer_name="MySecureApp"
)

# Generate QR code
import qrcode
qr = qrcode.make(uri)
qr.save('totp_qr.png')
```

I tested this by scanning the generated QR code with Google Authenticator on my phone. The codes on my phone and in the Python script matched perfectly, updating every 30 seconds in sync.

### TOTP vs SMS 2FA

TOTP is significantly more secure than SMS-based 2FA:
- **SMS**: Can be intercepted, SIM swapping attacks, relies on carrier security
- **TOTP**: Works offline, no interception possible, secret never transmitted

The TOTP secret is only shared once during setup (ideally via QR code), and after that, all code generation happens locally on the device.

---

## Section 5: Brute-Force Attack Simulation

### Understanding the Attack

A brute-force attack tries every possible password until finding the correct one. A dictionary attack is more efficient - it tries common passwords first (password, 123456, qwerty, etc.) before attempting random combinations.

### Implementation

I simulated a dictionary attack against different hash types:

```python
def brute_force_attack(target_hash, hash_type):
    common_passwords = ['password', '123456', 'admin', 'letmein', 'qwerty']
    attempts = 0
    
    for guess in common_passwords:
        attempts += 1
        
        if hash_type == 'md5':
            guess_hash = hashlib.md5(guess.encode()).hexdigest()
        elif hash_type == 'sha256':
            guess_hash = hashlib.sha256(guess.encode()).hexdigest()
        
        if guess_hash == target_hash:
            return f"Cracked in {attempts} attempts!"
```

### Results

Testing against the password "password":

**MD5**: Cracked in milliseconds (attempt #1)
**SHA-256**: Cracked in milliseconds (attempt #1)
**bcrypt**: Didn't even attempt - would take days/weeks/years

With just 5 common passwords, the fast hashes were cracked instantly. A real attacker would use wordlists containing millions of passwords. On a modern GPU:
- MD5: Can try ~50 billion hashes per second
- bcrypt (work factor 12): Can try ~100 hashes per second

That's a difference of 500 million times slower. If cracking a bcrypt hash would take 10 years, the equivalent MD5 hash would take 0.6 seconds.

### Why bcrypt Defeats Brute-Force

bcrypt's intentional slowness makes brute-force attacks economically infeasible. Even with powerful hardware, trying millions of password guesses takes impractically long. The work factor can be increased over time as computers improve, maintaining security.

This is why we accept the 100-200ms delay during login - that same delay protects us from attacks.

---

## Section 6: Complete Authentication System

### Bringing It All Together

The final exercise integrated everything into a user authentication class:

```python
class SecureAuthSystem:
    def __init__(self):
        self.users = {}  # Mock database
    
    def register_user(self, username, password):
        # 1. Check password strength
        strength = analyze_password_strength(password)
        if strength < 5:
            return "Password too weak"
        
        # 2. Hash password with bcrypt (auto-salts)
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        # 3. Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        # 4. Store in database
        self.users[username] = {
            'password_hash': password_hash,
            'totp_secret': totp_secret
        }
        
        return totp_secret  # User needs this for 2FA setup
    
    def authenticate(self, username, password, totp_code):
        # 1. Check if user exists
        if username not in self.users:
            return False
        
        user = self.users[username]
        
        # 2. Verify password
        password_valid = bcrypt.checkpw(
            password.encode(),
            user['password_hash']
        )
        
        # 3. Verify TOTP code
        totp = pyotp.TOTP(user['totp_secret'])
        totp_valid = totp.verify(totp_code)
        
        return password_valid and totp_valid
```

### Testing the System

**Registration**:
```python
auth = SecureAuthSystem()
secret = auth.register_user("zohaib", "SecureP@ss2025!")
# Generates QR code for TOTP setup
```

**Login**:
```python
# Get current TOTP code from authenticator app: "123456"
success = auth.authenticate("zohaib", "SecureP@ss2025!", "123456")
# Returns True if both password and code are correct
```

The system rejects weak passwords, automatically handles secure hashing and salting, and requires both factors for authentication. This is production-level security implementation.

---

## Key Security Principles Applied

### Defence in Depth

Multiple security layers work together:
1. **Password strength requirements** - First line of defence
2. **bcrypt hashing** - Protects stored credentials
3. **Automatic salting** - Defeats rainbow tables
4. **Optional pepper** - Protects against database theft
5. **TOTP 2FA** - Protects against password compromise

If an attacker bypasses one layer, others still protect the system.

### Confidentiality (CIA Triad)

Even if the database is stolen:
- Passwords cannot be read (hashed, not plaintext)
- Each password is uniquely salted (no rainbow table attacks)
- Pepper adds additional secret (if implemented)
- 2FA secrets enable account access control

### Practical Security Trade-offs

**Login speed vs security**: bcrypt's slowness adds ~200ms to login. This is acceptable for the massive security improvement.

**Usability vs security**: 2FA adds friction to login process. However, the security benefit far outweighs the minor inconvenience.

**Storage vs security**: Salts increase database size slightly. The security benefit is worth it.

Good security involves making intelligent trade-offs that maximize protection while maintaining usability.

---

## Real-World Applications

### Industry Standard Practices

This workshop implemented what major companies use:
- **GitHub, Google, AWS**: All use bcrypt or Argon2 for password storage
- **Banking apps**: Universally require 2FA
- **Password managers**: Use similar strength analysis before storing passwords

### Common Vulnerabilities Avoided

**Plaintext storage**: Still happens. In 2019, Facebook stored millions of passwords in plaintext in internal logs. Our system prevents this entirely.

**Weak hashing**: In 2012, LinkedIn used unsalted SHA-1 for 6.5 million passwords. All were cracked within days. Our system uses bcrypt with automatic salting.

**No 2FA**: In 2020, Twitter accounts were compromised because they only used passwords. Our system requires 2FA.

### What We Didn't Cover

Production systems also need:
- Account lockout after failed attempts (prevent online brute-force)
- Rate limiting on authentication endpoints
- Secure password reset flows
- Session management and token security
- Backup codes for 2FA recovery
- Audit logging of authentication events

These are important but beyond the scope of this workshop. The foundations we built are solid starting points.

---

## Challenges and Learning

### Understanding the TOTP Time Window

Initially confusing that TOTP codes are valid for slightly more than 30 seconds. The `verify()` method actually checks the current code, the previous code, and the next code to account for clock drift between server and device. This prevents frustrating failures when someone enters a code right as it changes.

### bcrypt Work Factor Selection

The work factor (12 in our case) determines how slow bcrypt is. Higher is more secure but slower:
- Work factor 10: ~100ms per hash
- Work factor 12: ~200ms per hash (2^12 rounds)
- Work factor 14: ~800ms per hash

You increase it over time as computers get faster. The goal is to make it just slow enough to be annoying for attackers but not so slow users notice during login.

### Salt Storage with bcrypt

One thing that confused me initially: with bcrypt, you don't need separate salt storage. The salt is embedded in the hash string itself. The `checkpw()` function extracts the salt from the stored hash automatically. This is why bcrypt is so convenient compared to manually implementing salting.

---

## Connection to Module and Career

### Networks and System Security Module

This workshop directly implements concepts we studied:
- **Authentication mechanisms**: From theory to practice
- **Cryptographic hashing**: Applied to real security problems
- **Access control**: Building systems that verify user identity
- **Attack mitigation**: Defending against common threats

### Career Relevance

For the three jobs from Week 1:

**FactSet**: Financial systems need robust authentication. Understanding password security, 2FA implementation, and secure credential storage is essential.

**Starling Bank**: Customer account security is critical. This workshop covers exactly what a banking application needs - strong hashing, 2FA, and defence against credential theft.

**Deloitte**: Security consultants must understand authentication systems to audit them. Being able to identify weak hashing, missing 2FA, or improper salt usage is a key skill.

Being able to explain "we use bcrypt with work factor 12 and mandatory TOTP 2FA" demonstrates practical security knowledge beyond just theory.

---

## Reflection

This workshop was probably the most practically useful so far. Authentication is something every application needs, and understanding how to do it securely is fundamental. The progression from weak (MD5) to strong (bcrypt + 2FA) clearly demonstrated why security best practices exist.

What surprised me most was how simple it is to implement strong security with the right libraries. bcrypt handles salting automatically, pyotp makes TOTP straightforward, and the entire system is maybe 100 lines of code. The hard part isn't the implementation - it's knowing what to implement and why.

The brute-force simulation really drove home why algorithm choice matters. Seeing that MD5 hashes crack in milliseconds while bcrypt would take years makes the theoretical discussions about "computational infeasibility" concrete.

One thing I'm still curious about: how do you handle password resets securely? If someone loses their password and their 2FA device, how do you verify their identity to let them back in? That's probably a whole additional workshop on recovery mechanisms and identity verification.

This workshop also highlighted the constant tension between security and usability. Every security measure adds friction. The art is finding the right balance - enough security to protect users without making the system frustrating to use.

---

## Next Steps

To build on this workshop:
- Implement account lockout after failed login attempts
- Add password reset functionality with email verification
- Store user data in actual database (SQLite/PostgreSQL) instead of dictionary
- Implement session tokens instead of re-authenticating every request
- Add rate limiting to prevent online brute-force attacks
- Explore Argon2 as alternative to bcrypt (newer, possibly better)

This practical work complements the Security+ study from Week 1 - the certification covers these concepts theoretically, while this workshop gave me hands-on implementation experience.
