# ecdsa-simulation
This repository contains a Python script that simulates communication using the Elliptic Curve Digital Signature Algorithm (ECDSA) between two parties, Alice and Bob. ECDSA is a widely used digital signature algorithm that provides a secure way to sign and verify messages.

## Getting Started

1. Clone this repository:
```bash
git clone https://github.com/Kairos-T/ecdsa-simulation
cd ecdsa-simulation
```

2. (Optional): Create a Python virtual environment
```bash
sudo python3 -m venv venv
source venv/bin/activate
```

3. Install required dependencies
```bash
pip install -r requirements.txt
```

4. Run the script:
```bash
python3 main.py
```

## Simulation Options
1. **Simulate Perfect Implementation**: Simulate ECDSA communication with a perfect implementation.
2. **Simulate with Tampered Message**: Simulate ECDSA communication with a tampered message to demonstrate the algorithm's ability to detect message tampering.

## Simulation Results (Sample)

### Main Menu
```
--------------------------------------------------


 _____   ____  ____   ____      _    
| ____| / ___||  _ \ / ___|    / \   
|  _|  | |    | | | |\___ \   / _ \  
| |___ | |___ | |_| | ___) | / ___ \ 
|_____| \____||____/ |____/ /_/   \_\
                                     

--------------------------------------------------
CTG Assignment CSF02 2023

This script simulates ECDSA communication between Alice and Bob.
It includes functions for generating ECDSA key pairs, signing and verifying
messages using the Elliptic Curve Digital Signature Algorithm (ECDSA).
Users can choose between a perfect implementation or a simulation with a tampered message,
demonstrating the ability of ECDSA to detect message tampering and ensure data integrity.

Menu:
1. Perfect Implementation
2. Tampered Message
3. Exit
Enter your choice (1, 2, or 3): 
```

### Perfect Implementation
```
Enter your choice (1, 2, or 3): 1

Alice's Side:
Alice's Private Key: 6dac1fb45b44ab85da8ff12a0a5daf71bf1a02e528698342acde443174a7dcf0
Alice's Public Key: ba894a6985753080f0a8159ecd305e46b79f2394ae6f21f907e7a58e06b46ad66e1c284e80f4ac22f075093403d3c10afdcee848b09cf791dea62a9124ca8d91

Message: CTG Assignment - Simulation of ECDSA
Message Hash: 74df74cd67764cc26b03fb5a43f66308b25b006ddf5c74d5e820d666c0c74a2c
Signature: 53ab71d3531af30ac981001e06a2983d9fd257ae0acf94077a7e0f20997bd6726e337c4c2339c4520586b750110b46953be2dba51e80e4d8e7ac922ad5d99111

Bob's Side:
Bob's Public Key: 80b7e4f4064aaf1f26f571bf9880f9f3bd87f3b2549b84aaccfcac65aa65140383fb852b87ed9dcf0acf091cb7bf5f663f8d7efc558bc5a2aafcb19fbfcad0d2
Verifying signature...

Signature is valid.
```

### Tampered Message
```
Enter your choice (1, 2, or 3): 2

Alice's Side:
Alice's Private Key: 6dac1fb45b44ab85da8ff12a0a5daf71bf1a02e528698342acde443174a7dcf0
Alice's Public Key: ba894a6985753080f0a8159ecd305e46b79f2394ae6f21f907e7a58e06b46ad66e1c284e80f4ac22f075093403d3c10afdcee848b09cf791dea62a9124ca8d91
Message: CTG Assignment - Simulation of ECDSA
Message Hash: 74df74cd67764cc26b03fb5a43f66308b25b006ddf5c74d5e820d666c0c74a2c
Signature: d7abec718b3215ffb16a93399ef61aeca13f54c62678ff39b3f47a91bbfba3879d98015a4d57cde73188f5d24ecd6a5d067841308c48be27f31c00662d6aa0d0

Bob's Side:
Bob's Public Key: 80b7e4f4064aaf1f26f571bf9880f9f3bd87f3b2549b84aaccfcac65aa65140383fb852b87ed9dcf0acf091cb7bf5f663f8d7efc558bc5a2aafcb19fbfcad0d2

Tampering the message...
Tampered Message:  CTG Assignment - Simulation of ECDSA (Tampered!)
Verifying signature...

Signature is invalid.
```
