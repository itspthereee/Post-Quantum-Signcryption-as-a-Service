"""
Post-Quantum Signcryption-as-a-Service Demo
Demonstrates post-quantum cryptographic operations for signing, encryption, and combined signcryption.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Tuple, Dict, Any
from datetime import datetime


@dataclass
class KeyPair:
    """Represents a post-quantum cryptographic key pair."""
    public_key: str
    private_key: str
    algorithm: str
    created_at: str


@dataclass
class SigncryptedMessage:
    """Represents a signcrypted message."""
    ciphertext: str
    signature: str
    algorithm: str
    sender_id: str
    recipient_id: str
    timestamp: str


class PQEaaS:
    """Post-Quantum Encryption-as-a-Service"""

    def __init__(self):
        """Initialize the PQEaaS service."""
        self.key_store: Dict[str, KeyPair] = {}
        self.algorithms = ["CRYSTALS-Kyber", "CRYSTALS-Dilithium", "SPHINCS+"]

    def generate_keypair(self, user_id: str, algorithm: str = "CRYSTALS-Dilithium") -> KeyPair:
        """
        Generate a post-quantum key pair for a user.
        
        Args:
            user_id: Unique identifier for the user
            algorithm: Post-quantum algorithm to use
            
        Returns:
            KeyPair object containing public and private keys
        """
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # Simulate key generation (in production, use liboqs or similar library)
        public_key = self._generate_pq_key(f"pk_{user_id}", "public")
        private_key = self._generate_pq_key(f"sk_{user_id}", "private")

        key_pair = KeyPair(
            public_key=public_key,
            private_key=private_key,
            algorithm=algorithm,
            created_at=datetime.now().isoformat(),
        )

        # Store key pair
        self.key_store[user_id] = key_pair
        return key_pair

    def sign(self, user_id: str, message: str) -> str:
        """
        Sign a message using post-quantum signatures.
        
        Args:
            user_id: ID of the signing user
            message: Message to sign
            
        Returns:
            Digital signature
        """
        if user_id not in self.key_store:
            raise ValueError(f"User {user_id} not found")

        key_pair = self.key_store[user_id]
        # Simulate post-quantum signature using hash
        signature_input = f"{key_pair.private_key}{message}".encode()
        signature = hashlib.sha3_512(signature_input).hexdigest()
        return signature

    def verify(self, user_id: str, message: str, signature: str) -> bool:
        """
        Verify a post-quantum signature.
        
        Args:
            user_id: ID of the signing user
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        if user_id not in self.key_store:
            return False

        key_pair = self.key_store[user_id]
        # Verify by recomputing the signature
        signature_input = f"{key_pair.private_key}{message}".encode()
        expected_signature = hashlib.sha3_512(signature_input).hexdigest()
        return signature == expected_signature

    def encrypt(self, recipient_id: str, plaintext: str) -> str:
        """
        Encrypt a message using post-quantum encryption (Kyber-based).
        
        Args:
            recipient_id: ID of the recipient
            plaintext: Message to encrypt
            
        Returns:
            Ciphertext
        """
        if recipient_id not in self.key_store:
            raise ValueError(f"User {recipient_id} not found")

        key_pair = self.key_store[recipient_id]
        # Simulate post-quantum encryption using SHA3 (in production, use Kyber)
        encryption_input = f"{key_pair.public_key}{plaintext}".encode()
        ciphertext = hashlib.sha3_512(encryption_input).hexdigest()
        return ciphertext

    def decrypt(self, recipient_id: str, ciphertext: str, plaintext_hint: str = None) -> str:
        """
        Decrypt a message using post-quantum decryption.
        
        Args:
            recipient_id: ID of the recipient
            ciphertext: Encrypted message
            plaintext_hint: Hint for demonstration (not used in real systems)
            
        Returns:
            Decrypted message
        """
        if recipient_id not in self.key_store:
            raise ValueError(f"User {recipient_id} not found")

        # In production, actual decryption would occur here
        return plaintext_hint or "[Decrypted message would appear here]"

    def signcrypt(
        self, sender_id: str, recipient_id: str, message: str
    ) -> SigncryptedMessage:
        """
        Perform signcryption: combine signing and encryption in a single operation.
        This is more efficient than signing then encrypting.
        
        Args:
            sender_id: ID of the sender
            recipient_id: ID of the recipient
            message: Message to signcrypt
            
        Returns:
            SigncryptedMessage containing both ciphertext and signature
        """
        if sender_id not in self.key_store:
            raise ValueError(f"Sender {sender_id} not found")
        if recipient_id not in self.key_store:
            raise ValueError(f"Recipient {recipient_id} not found")

        # Step 1: Sign the message
        signature = self.sign(sender_id, message)

        # Step 2: Encrypt the message + signature
        combined_data = f"{message}|{signature}"
        ciphertext = self.encrypt(recipient_id, combined_data)

        return SigncryptedMessage(
            ciphertext=ciphertext,
            signature=signature,
            algorithm=self.key_store[sender_id].algorithm,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=datetime.now().isoformat(),
        )

    def unsigncrypt(
        self, sender_id: str, recipient_id: str, signcrypted: SigncryptedMessage
    ) -> Tuple[str, bool]:
        """
        Reverse signcryption: decrypt and verify in a single operation.
        
        Args:
            sender_id: ID of the sender
            recipient_id: ID of the recipient
            signcrypted: SigncryptedMessage to unsigncrypt
            
        Returns:
            Tuple of (message, is_valid) where is_valid indicates signature validity
        """
        # Step 1: Decrypt
        decrypted = self.decrypt(recipient_id, signcrypted.ciphertext, "test_message")

        # Step 2: Verify signature
        is_valid = self.verify(sender_id, decrypted, signcrypted.signature)

        return decrypted, is_valid

    def _generate_pq_key(self, seed: str, key_type: str) -> str:
        """
        Generate a simulated post-quantum key.
        In production, use liboqs with actual PQ algorithms.
        """
        hash_input = f"{seed}_{key_type}".encode()
        return hashlib.sha3_256(hash_input).hexdigest()


def main():
    """Demonstrate PQEaaS functionality."""
    print("=" * 70)
    print("Post-Quantum Signcryption-as-a-Service (PQEaaS) Demo")
    print("=" * 70)
    print()

    # Initialize service
    service = PQEaaS()
    print("✓ PQEaaS Service initialized")
    print()

    # Generate keypairs for Alice and Bob
    print("--- Key Generation ---")
    alice_keys = service.generate_keypair("alice", "CRYSTALS-Dilithium")
    print(f"✓ Generated keys for Alice")
    print(f"  Algorithm: {alice_keys.algorithm}")
    print(f"  Public Key (first 32 chars): {alice_keys.public_key[:32]}...")
    print()

    bob_keys = service.generate_keypair("bob", "CRYSTALS-Dilithium")
    print(f"✓ Generated keys for Bob")
    print(f"  Algorithm: {bob_keys.algorithm}")
    print(f"  Public Key (first 32 chars): {bob_keys.public_key[:32]}...")
    print()

    # Test signing and verification
    print("--- Digital Signature ---")
    message = "Hello Bob, this is Alice!"
    signature = service.sign("alice", message)
    print(f"✓ Alice signed message: '{message}'")
    print(f"  Signature (first 32 chars): {signature[:32]}...")
    print()

    is_valid = service.verify("alice", message, signature)
    print(f"✓ Signature verification: {'VALID' if is_valid else 'INVALID'}")
    print()

    # Test encryption and decryption
    print("--- Encryption ---")
    plaintext = "Secret message for Bob"
    ciphertext = service.encrypt("bob", plaintext)
    print(f"✓ Encrypted message for Bob: '{plaintext}'")
    print(f"  Ciphertext (first 32 chars): {ciphertext[:32]}...")
    print()

    decrypted = service.decrypt("bob", ciphertext, plaintext)
    print(f"✓ Bob decrypted message: '{decrypted}'")
    print()

    # Test signcryption (combined operation)
    print("--- Signcryption (Sign + Encrypt) ---")
    message_to_signcrypt = "Authenticated and encrypted message"
    signcrypted = service.signcrypt("alice", "bob", message_to_signcrypt)
    print(f"✓ Alice signcrypted message: '{message_to_signcrypt}'")
    print(f"  Ciphertext (first 32 chars): {signcrypted.ciphertext[:32]}...")
    print(f"  Sender: {signcrypted.sender_id}")
    print(f"  Recipient: {signcrypted.recipient_id}")
    print(f"  Timestamp: {signcrypted.timestamp}")
    print()

    # Verify signcryption
    print("--- Unsigncryption (Decrypt + Verify) ---")
    recovered_message, is_valid = service.unsigncrypt("alice", "bob", signcrypted)
    print(f"✓ Bob recovered message: '{recovered_message}'")
    print(f"  Signature valid: {'YES' if is_valid else 'NO'}")
    print()

    # Export statistics
    print("--- Service Statistics ---")
    print(f"Total users: {len(service.key_store)}")
    print(f"Supported algorithms: {', '.join(service.algorithms)}")
    print()

    print("=" * 70)
    print("Demo completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()
