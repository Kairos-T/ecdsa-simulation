import hashlib
import ecdsa
from art import *


def generate_keypair():
    """
    Generate a random ECDSA key pair.

    Returns:
        tuple: A tuple containing the private key and corresponding public key.
    """
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def sign_message(private_key, message):
    """
    Sign a message using ECDSA.

    Args:
        private_key (ecdsa.SigningKey): The private key for signing.
        message (str): The message to be signed.

    Returns:
        bytes: The signature of the message.
    """
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(message_hash)
    print(f"Message: {message}")
    print(f"Message Hash: {message_hash.hex()}")
    print(f"Signature: {signature.hex()}")
    return signature

def verify_signature(public_key, message, signature):
    """
    Verify the signature of a message using ECDSA.

    Args:
        public_key (ecdsa.VerifyingKey): The public key for verification.
        message (str): The original message.
        signature (bytes): The signature to be verified.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    message_hash = hashlib.sha256(message.encode()).digest()
    print("Verifying signature...\n")
    try:
        public_key.verify(signature, message_hash)
        print("Signature is valid.")
        return True
    except ecdsa.BadSignatureError:
        print("Signature is invalid.")
        return False

def simulate_ecdsa_communication():
    """
    Simulate ECDSA communication between Alice and Bob.
    """
    # Alice generates key pair
    alice_private_key, alice_public_key = generate_keypair()

    # Bob generates key pair
    bob_private_key, bob_public_key = generate_keypair()

    while True:
        print("\nMenu:")
        print("1. Perfect Implementation")
        print("2. Tampered Message")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            # Perfect Implementation
            message = "CTG Assignment - Simulation of ECDSA"
            print("\nAlice's Side:")
            print(f"Alice's Private Key: {alice_private_key.to_string().hex()}")
            print(f"Alice's Public Key: {alice_public_key.to_string().hex()}\n")
            signature = sign_message(alice_private_key, message)
            print("\nBob's Side:")
            print(f"Bob's Public Key: {bob_public_key.to_string().hex()}")
            verify_signature(alice_public_key, message, signature)
        elif choice == '2':
            # Tampered Message
            message = "CTG Assignment - Simulation of ECDSA"
            print("\nAlice's Side:")
            print(f"Alice's Private Key: {alice_private_key.to_string().hex()}")
            print(f"Alice's Public Key: {alice_public_key.to_string().hex()}")
            signature = sign_message(alice_private_key, message)
            print("\nBob's Side:")
            print(f"Bob's Public Key: {bob_public_key.to_string().hex()}")
            print("\nTampering the message...")
            message += " (Tampered!)"
            print("Tampered Message: ", message)
            verify_signature(alice_public_key, message, signature)
        elif choice == '3':
            print("Exiting the simulation.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    print("-" * 50 + "\n\n")
    print(text2art("ECDSA"))
    print("-" * 50)
    print("CTG Assignment CSF02 2023\n")
    print(
        "This script simulates ECDSA communication between Alice and Bob.\n"
        "It includes functions for generating ECDSA key pairs, signing and verifying\n"
        "messages using the Elliptic Curve Digital Signature Algorithm (ECDSA).\n"
        "Users can choose between a perfect implementation or a simulation with a tampered message,\n"
        "demonstrating the ability of ECDSA to detect message tampering and ensure data integrity."
    )
    simulate_ecdsa_communication()
