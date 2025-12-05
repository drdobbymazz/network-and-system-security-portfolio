# Week 2: RSA Encryption and Secure Communication

**Module**: Networks and System Security  
**Student**: Zohaib Khokhar  
**Date**: December 2025  
**Topic**: RSA Algorithm and Socket Programming

---

## Overview

This week focused on implementing secure communication using RSA encryption and Python sockets. We built a sender-receiver system that demonstrates hybrid encryption - combining RSA's security with AES's speed. This is essentially how HTTPS and encrypted messaging work in practice.

---

## What is Hybrid Encryption?

The system uses two types of encryption:

**RSA (Asymmetric)**: Uses public/private key pairs. Anyone can encrypt with the public key, but only the private key holder can decrypt. The problem is RSA is slow for large data.

**AES (Symmetric)**: Uses one key for both encryption and decryption. Very fast, but you need to securely share the key first.

**The Solution**: Use RSA to securely share an AES key, then use AES for the actual message. This gives you both security and speed.

---

## Implementation

### Step 1: Generate Keys

```python
# generate_keys.py
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

Creates a 2048-bit RSA key pair and saves them as `private_key.pem` and `public_key.pem`. The 2048-bit size is current security standard - large enough to be secure but not so large it's impractically slow.

### Step 2: Receiver (Server)

The receiver listens on port 65432 and performs two decryption steps when data arrives:

```python
# Decrypt the AES key using RSA private key
aes_key = private_key.decrypt(encrypted_key, padding.OAEP(...))

# Decrypt the message using the recovered AES key
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
message = decryptor.update(encrypted_message) + decryptor.finalize()
```

The socket implementation uses TCP (`SOCK_STREAM`) for reliable delivery. The receive loop accumulates data chunks because network packets might arrive separately - you can't assume everything comes in one `recv()` call.

### Step 3: Sender (Client)

The sender encrypts in reverse order:

```python
# 1. Generate random AES key and IV
aes_key = os.urandom(32)  # 256-bit key for AES-256
iv = os.urandom(16)       # Initialization vector

# 2. Encrypt message with AES
encrypted_message = encryptor.update(message) + encryptor.finalize()

# 3. Encrypt the AES key with recipient's RSA public key
encrypted_key = public_key.encrypt(aes_key, padding.OAEP(...))

# 4. Send everything together
payload = pickle.dumps((encrypted_key, iv, encrypted_message))
```

The IV (initialization vector) is random and must be unique for each message. Even encrypting the same message twice produces different ciphertext thanks to the IV. It doesn't need to be secret - it's sent in plaintext alongside the encrypted data.

---

## Running the System

Setup:
```bash
pip install cryptography
python generate_keys.py  # Creates the key pair
```

Terminal 1 (Receiver):
```bash
python receiver.py
# Output: 🔒 Waiting for connection...
```

Terminal 2 (Sender):
```bash
python sender.py
# Output: ✅ Encrypted message sent!
```

The receiver then displays: `🔓 Decrypted message: Hello from the secure sender! This is confidential.`

Watching the encrypted data in transit shows complete gibberish - without the AES key (which is itself encrypted), the message is unreadable.

---

## Security Concepts

### Confidentiality (CIA Triad)

This directly demonstrates confidentiality - only the intended recipient with the private key can decrypt the message. Network intermediaries see only encrypted bytes.

### Defence in Depth

Multiple security layers work together:
- AES encrypts the message content
- RSA protects the AES key
- OAEP padding prevents RSA attacks
- Random IV prevents pattern detection

### Key Management

The private key is critical - if it's compromised, all intercepted messages can be decrypted. In production systems, private keys would be password-protected or stored in hardware security modules (HSMs).

---

## Real-World Applications

### HTTPS/TLS
When you see the padlock in your browser:
1. Browser and server exchange public keys (via certificates)
2. They establish a symmetric key using asymmetric encryption
3. Actual data transfer uses the fast symmetric key
4. Keys are rotated periodically for forward secrecy

This workshop code is essentially a simplified TLS handshake.

### End-to-End Encryption
Apps like Signal use similar principles - messages are encrypted with the recipient's public key, and only their private key can decrypt. Not even the service provider can read messages.

---

## Challenges and Learning

**Understanding the data flow**: Initially confusing that the payload contains three pieces (encrypted AES key, IV, encrypted message). The IV doesn't need encryption because knowing it doesn't help an attacker - it just initializes the cipher.

**Socket programming**: The `recv(4096)` buffer size and loop structure were new to me. The loop is essential because TCP doesn't guarantee all data arrives in one packet.

**CFB mode**: We used AES in CFB (Cipher Feedback) mode, which handles variable-length messages without padding. Different modes (CBC, GCM, etc.) have different properties - CFB essentially turns a block cipher into a stream cipher.

**OAEP padding**: The padding in RSA encryption adds randomness to prevent attacks. Without it, RSA would be vulnerable to certain mathematical attacks.

---

## Questions That Arose

1. **Public key distribution**: How do you securely get the recipient's public key in the first place? In reality, this is where certificate authorities and PKI come in.

2. **Perfect forward secrecy**: If someone records traffic now and steals the private key later, they could decrypt old messages. Modern protocols use ephemeral keys that are discarded after each session.

3. **Message authentication**: This system only provides confidentiality. In production, you'd also want to verify the message hasn't been tampered with (using HMAC or GCM mode).

---

## Connection to Studies and Career

This workshop connects directly to what we studied about network security protocols. The hybrid encryption model is exactly what SSL/TLS, PGP, and IPSec use in practice.

For the three jobs I researched in Week 1:
- **FactSet**: Financial data needs encryption in transit and at rest
- **Starling Bank**: Customer data protection requires understanding of encryption implementation
- **Deloitte**: Security consultants need to review code and identify cryptographic weaknesses

Being able to explain "we use RSA to establish a secure channel, then AES for data transfer" is a practical skill all three roles would value.

---

## Reflection

Actually implementing encryption made it feel much more concrete than just studying the theory. The hybrid approach is elegant - using the right tool for each part of the job rather than forcing one solution to do everything.

What surprised me was how accessible secure communication is with modern libraries. The `cryptography` library handles the complex maths, so we can focus on using it correctly. However, this also means we're trusting these libraries implicitly - if there's a vulnerability in the library or it's misconfigured, security falls apart.

The workshop also highlighted gaps in my knowledge around key distribution and certificate verification. Understanding the encryption algorithm is one thing, but securely establishing trust between parties is a whole additional layer of complexity. That's something I need to explore more as I continue with the Security+ study plan from Week 1.

---

## Next Steps

To build on this:
- Add digital signatures to verify sender authenticity
- Implement certificate verification to simulate browser behavior
- Try running sender/receiver on different machines across a network
- Explore AES-GCM mode which provides both encryption and authentication

This practical experience feeds directly into the Security+ certification I'm working toward, particularly the cryptography domain.
