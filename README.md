# TARS: Traceable and Linkable Ring Signature

This project implements a Traceable, Anonymous, and Linkable Ring Signature scheme in Python using the SageMath library.

## Features

- **Anonymity**: Users can sign messages on behalf of a group (ring) without revealing their specific identity.
- **Traceability**: A designated group of threshold authorities (Tracers) can cooperate to revoke a user's anonymity and identify the original signer if necessary.
- **Linkability**: Signatures created by the same user for different messages can be linked together, proving they come from the same (anonymous) source. This is useful for preventing abuse like spamming.
- **Performance**: Utilizes windowed pre-computation (`PowerTable`) for efficient elliptic curve scalar multiplication.

## Cryptographic Primitives

- Elliptic Curve Cryptography (ECC) over extension fields.
- Weil Pairings.
- Shamir's Secret Sharing for threshold traceability.
- ElGamal Encryption for identity encapsulation.
- Non-Interactive Zero-Knowledge (NIZK) proofs for demonstrating ring membership and signature correctness.

## Project Structure

```
TARS/
├── core/
│   ├── config/
│   │   └── params.json          # System parameters, constants
│   ├── crypto/
│   │   ├── pairing.py           # Pairing, group ops, PowerTable, SystemSetup
│   │   ├── schnorr.py           # Schnorr NIZK protocol
│   │   └── hash.py              # Hashing utility
│   ├── protocol/
│   │   ├── ring_signature.py    # Main ring signature sign/verify logic
│   │   ├── nizk.py              # Simulation-based NIZK for the ring proof
│   │   └── trace.py             # Tracing protocol logic
│   └── entities/
│       ├── user.py              # User entity class
│       └── tracer.py            # Tracer entity class
├── tests/                       # (Placeholder for unit tests)
│   └── ...
├── main.py                      # Main entry point and demonstration
└── README.md
```

## Setup & Running

1.  **Dependencies**: This project requires `SageMath`. You need to run the code within a SageMath environment.
    ```bash
    # Install SageMath (if you haven't already)
    # See https://www.sagemath.org/ for instructions

    # To run a script
    sage main.py
    ```

2.  **Run the Demonstration**:
    ```bash
    sage main.py
    ```
    The main script will:
    1.  Initialize system parameters.
    2.  Create a set of users and tracers.
    3.  Have one user sign a message.
    4.  Verify the signature.
    5.  Demonstrate the tracing protocol to reveal the signer's identity.
    6.  Demonstrate the linkability feature.