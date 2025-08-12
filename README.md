# libTARS: Threshold Anonymous Ring Signature System

This project implements a **Threshold Anonymous Ring Signature (TARS)** system with traceability in Python using the SageMath library. The system provides anonymous ring signatures with threshold-based traceability, allowing designated authorities to cooperate to identify signers when necessary.

## Features

- **Anonymity**: Users can sign messages on behalf of a group (ring) without revealing their specific identity
- **Threshold Traceability**: A designated group of threshold authorities (Tracers) can cooperate to revoke a user's anonymity and identify the original signer
- **Linkability**: Signatures created by the same user for different messages can be linked together, proving they come from the same (anonymous) source
- **Performance**: Utilizes windowed pre-computation (`PowerTable`) for efficient elliptic curve scalar multiplication
- **CLI Interface**: Comprehensive command-line interface for all operations
- **Flexible Configuration**: Support for custom file paths and system parameters

## Cryptographic Primitives

- **Elliptic Curve Cryptography (ECC)** over extension fields
- **Weil Pairings** for cryptographic operations
- **Shamir's Secret Sharing** for threshold traceability
- **ElGamal Encryption** for identity encapsulation
- **Non-Interactive Zero-Knowledge (NIZK)** proofs for demonstrating ring membership and signature correctness
- **Schnorr Signatures** for proof generation and verification

## System Architecture

The system consists of three main entities:

- **KGC (Key Generation Center)**: Generates system parameters and tracer key shares
- **User**: Generates keys, creates ring signatures, and verifies signatures  
- **Tracer**: Performs partial decryption to recover signer identity

## Project Structure

```
libTARS/
├── core/
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── nizk.py              # NIZK proof implementation
│   │   ├── public_params.py     # Public parameters and utilities
│   │   └── schnorr.py           # Schnorr signature implementation
│   ├── entities/
│   │   ├── __init__.py
│   │   ├── kgc.py               # Key Generation Center
│   │   ├── tracer.py            # Tracer entity
│   │   └── user.py              # User entity
│   └── protocol/
│       ├── __init__.py
│       ├── signature.py         # Ring signature protocol
│       └── trace.py             # Tracing protocol
├── config/
│   ├── kgc/                     # KGC keys and parameters
│   ├── tracer/                  # Tracer keys
│   ├── user/                    # User keys
│   └── params.json              # System parameters
├── docs/
│   ├── CONFIGURATION.md         # Configuration guide
│   └── TRACER_USAGE.md          # Tracer usage documentation
├── temp/                        # Temporary test files
├── libTARS_cli.py               # Command-line interface
├── main.py                      # Main entry point
├── test_libTARS_cli.sh          # Test script
├── USAGE.md                     # Comprehensive usage guide
└── README.md                    # This file
```

## Quick Start

### Prerequisites

1. **Install SageMath**: This project requires SageMath. See [https://www.sagemath.org/](https://www.sagemath.org/) for installation instructions.

2. **Create Directory Structure**:
   ```bash
   mkdir -p config/{kgc,tracer,user} temp
   ```

### Basic Usage

1. **Setup System**:
   ```bash
   python libTARS_cli.py kgc setup
   ```

2. **Generate Tracer Keys**:
   ```bash
   python libTARS_cli.py kgc tracerkeygen
   ```

3. **Generate User Keys**:
   ```bash
   python libTARS_cli.py user keygen 1001
   python libTARS_cli.py user keygen 1002
   python libTARS_cli.py user keygen 1003
   ```

4. **Create and Sign Message**:
   ```bash
   echo "Test message" > temp/test_message.txt
   python libTARS_cli.py user sign 1001 temp/test_message.txt 1001,1002,1003 -o temp/signature.json
   ```

5. **Verify Signature**:
   ```bash
   python libTARS_cli.py user verify temp/test_message.txt -i temp/signature.json
   ```

6. **Trace Signer** (requires threshold tracers):
   ```bash
   python libTARS_cli.py tracer partial_decrypt 1 -k config/tracer/tracer_1_key.json -i temp/signature.json -o temp/partial_1.json
   python libTARS_cli.py tracer partial_decrypt 2 -k config/tracer/tracer_2_key.json -i temp/signature.json -o temp/partial_2.json
   python libTARS_cli.py tracer recover -i temp/signature.json -s temp/partial_1.json,temp/partial_2.json
   ```

## Command-Line Interface

The project provides a comprehensive CLI with the following modules:

- **KGC Commands**: System setup and tracer key generation
- **User Commands**: Key generation, signing, and verification
- **Tracer Commands**: Partial decryption and identity recovery

For detailed usage instructions, see [USAGE.md](USAGE.md).

## Running Tests

Execute the test script to verify the complete workflow:

```bash
bash test_libTARS_cli.sh
```

This script demonstrates:
1. System setup and key generation
2. User key generation for multiple users
3. Ring signature creation and verification
4. Threshold-based signer tracing

## Configuration

- **System Parameters**: Configured in `config/params.json`
- **Key Management**: Keys are stored in JSON format in respective directories
- **File Paths**: All paths can be customized via command-line options

## Security Considerations

- **Key Management**: Always backup your keys before overwriting them
- **Threshold Security**: The number of tracers required for recovery is configured in system parameters
- **Private Keys**: Keep private keys secure and never share them
- **File Permissions**: Ensure proper file permissions for sensitive key files

## Documentation

- **[USAGE.md](USAGE.md)**: Comprehensive API usage guide
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**: Configuration details
- **[docs/TRACER_USAGE.md](docs/TRACER_USAGE.md)**: Tracer-specific usage

