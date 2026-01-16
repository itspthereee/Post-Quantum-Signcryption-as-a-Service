"""
PQEaaS REST API Demo
Demonstrates how to use PQEaaS as a service with example API calls and responses.
"""

import json
from typing import Dict, Any
from demo import PQEaaS, SigncryptedMessage


class PQEaaSAPI:
    """REST API wrapper for Post-Quantum Signcryption-as-a-Service."""

    def __init__(self):
        """Initialize the API with the PQEaaS service."""
        self.service = PQEaaS()

    def _format_response(self, success: bool, data: Any = None, error: str = None) -> Dict:
        """Format a standardized API response."""
        response = {"success": success, "timestamp": str(__import__("datetime").datetime.now())}
        if data:
            response["data"] = data
        if error:
            response["error"] = error
        return response

    def keygen(self, user_id: str, algorithm: str = "CRYSTALS-Dilithium") -> Dict:
        """
        API Endpoint: POST /api/keygen
        Generate a new keypair for a user.
        """
        try:
            key_pair = self.service.generate_keypair(user_id, algorithm)
            return self._format_response(
                True,
                {
                    "user_id": user_id,
                    "algorithm": key_pair.algorithm,
                    "public_key": key_pair.public_key,
                    "created_at": key_pair.created_at,
                },
            )
        except Exception as e:
            return self._format_response(False, error=str(e))

    def sign(self, user_id: str, message: str) -> Dict:
        """
        API Endpoint: POST /api/sign
        Sign a message with a user's private key.
        """
        try:
            signature = self.service.sign(user_id, message)
            return self._format_response(
                True,
                {
                    "user_id": user_id,
                    "message": message,
                    "signature": signature,
                },
            )
        except Exception as e:
            return self._format_response(False, error=str(e))

    def verify(self, user_id: str, message: str, signature: str) -> Dict:
        """
        API Endpoint: POST /api/verify
        Verify a signature.
        """
        try:
            is_valid = self.service.verify(user_id, message, signature)
            return self._format_response(
                True,
                {
                    "user_id": user_id,
                    "message": message,
                    "signature_valid": is_valid,
                },
            )
        except Exception as e:
            return self._format_response(False, error=str(e))

    def encrypt(self, recipient_id: str, plaintext: str) -> Dict:
        """
        API Endpoint: POST /api/encrypt
        Encrypt a message for a recipient.
        """
        try:
            ciphertext = self.service.encrypt(recipient_id, plaintext)
            return self._format_response(
                True,
                {
                    "recipient_id": recipient_id,
                    "plaintext_length": len(plaintext),
                    "ciphertext": ciphertext,
                },
            )
        except Exception as e:
            return self._format_response(False, error=str(e))

    def signcrypt(self, sender_id: str, recipient_id: str, message: str) -> Dict:
        """
        API Endpoint: POST /api/signcrypt
        Signcrypt a message (sign + encrypt in one operation).
        """
        try:
            signcrypted = self.service.signcrypt(sender_id, recipient_id, message)
            return self._format_response(
                True,
                {
                    "sender_id": signcrypted.sender_id,
                    "recipient_id": signcrypted.recipient_id,
                    "message": message,
                    "ciphertext": signcrypted.ciphertext,
                    "signature": signcrypted.signature,
                    "algorithm": signcrypted.algorithm,
                    "timestamp": signcrypted.timestamp,
                },
            )
        except Exception as e:
            return self._format_response(False, error=str(e))

    def unsigncrypt(
        self, sender_id: str, recipient_id: str, ciphertext: str, signature: str
    ) -> Dict:
        """
        API Endpoint: POST /api/unsigncrypt
        Unsigncrypt a message (decrypt + verify in one operation).
        """
        try:
            signcrypted = SigncryptedMessage(
                ciphertext=ciphertext,
                signature=signature,
                algorithm="CRYSTALS-Dilithium",
                sender_id=sender_id,
                recipient_id=recipient_id,
                timestamp=str(__import__("datetime").datetime.now()),
            )
            message, is_valid = self.service.unsigncrypt(sender_id, recipient_id, signcrypted)
            return self._format_response(
                True,
                {
                    "sender_id": sender_id,
                    "recipient_id": recipient_id,
                    "message": message,
                    "signature_valid": is_valid,
                },
            )
        except Exception as e:
            return self._format_response(False, error=str(e))


def demo_api_calls():
    """Demonstrate PQEaaS API usage."""
    print("=" * 70)
    print("PQEaaS REST API Demo")
    print("=" * 70)
    print()

    api = PQEaaSAPI()

    # Example 1: Generate keypairs
    print("--- API Call 1: Generate keypair for Alice ---")
    response = api.keygen("alice")
    print_api_response(response)
    print()

    print("--- API Call 2: Generate keypair for Bob ---")
    response = api.keygen("bob")
    print_api_response(response)
    print()

    # Example 2: Sign a message
    print("--- API Call 3: Alice signs a message ---")
    response = api.sign("alice", "Hello Bob, this is Alice!")
    print_api_response(response)
    signature = response["data"]["signature"]
    print()

    # Example 3: Verify a signature
    print("--- API Call 4: Verify Alice's signature ---")
    response = api.verify("alice", "Hello Bob, this is Alice!", signature)
    print_api_response(response)
    print()

    # Example 4: Encrypt a message
    print("--- API Call 5: Encrypt message for Bob ---")
    response = api.encrypt("bob", "Secret message for Bob")
    print_api_response(response)
    ciphertext = response["data"]["ciphertext"]
    print()

    # Example 5: Signcrypt (combined operation)
    print("--- API Call 6: Signcrypt message (Alice to Bob) ---")
    response = api.signcrypt("alice", "bob", "Authenticated and encrypted content")
    print_api_response(response)
    signcrypted_ct = response["data"]["ciphertext"]
    signcrypted_sig = response["data"]["signature"]
    print()

    # Example 6: Unsigncrypt
    print("--- API Call 7: Unsigncrypt message (Bob receives from Alice) ---")
    response = api.unsigncrypt("alice", "bob", signcrypted_ct, signcrypted_sig)
    print_api_response(response)
    print()

    print("=" * 70)
    print("API Demo completed successfully!")
    print("=" * 70)


def print_api_response(response: Dict):
    """Pretty print an API response."""
    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    demo_api_calls()
