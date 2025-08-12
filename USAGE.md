# libTARS API Usage Guide

## Overview

libTARS is a threshold anonymous ring signature system with traceability. This guide explains how to use the command-line interface (CLI) for all operations.

## System Architecture

The system consists of three main entities:
- **KGC (Key Generation Center)**: Generates system parameters and tracer key shares
- **User**: Generates keys, creates ring signatures, and verifies signatures
- **Tracer**: Performs partial decryption to recover signer identity

## Prerequisites

1. Ensure you have the required dependencies installed
2. Create the necessary directory structure:
   ```
   config/
   ├── kgc/
   ├── tracer/
   └── user/
   ```

## Command Structure

All commands follow the pattern:
```bash
python libTARS_cli.py <module> <command> [arguments] [options]
```

## KGC Commands

### 1. Setup - Generate System Master Key and Public Key

**Command:**
```bash
python libTARS_cli.py kgc setup [options]
```

**Options:**
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-k, --key`: KGC key file (default: `config/kgc/key.json`)

**Example:**
```bash
python libTARS_cli.py kgc setup -p config/params.json -k config/kgc/key.json
```

**What it does:**
- Generates system master key `s` and public key `Q`
- Saves to `key.json` and updates `params.json`
- **Warning**: This will overwrite existing keys and invalidate all user/tracer keys

### 2. Tracer Key Generation - Generate Tracer Key Shares

**Command:**
```bash
python libTARS_cli.py kgc tracerkeygen [options]
```

**Options:**
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-k, --key`: KGC key file (default: `config/kgc/key.json`)
- `-o, --output`: Output file for all tracer keys (default: `config/tracer/tracer_keys.json`)
- `-sf, --single-key-file-fmt`: Single tracer key file format (default: `config/tracer/tracer_{}_key.json`)
- `-spf, --single-public-key-file-fmt`: Single tracer public key file format (default: `config/tracer/tracer_{}_pub.json`)

**Example:**
```bash
python libTARS_cli.py kgc tracerkeygen -p config/params.json -k config/kgc/key.json -o config/tracer/tracer_keys.json -sf "config/tracer/tracer_{}_key.json" -spf "config/tracer/tracer_{}_pub.json"
```

**What it does:**
- Generates Shamir secret sharing for tracer keys
- Creates individual tracer key files and public key files
- Supports threshold-based tracing

## User Commands

### 1. Key Generation - Generate User Key Pair

**Command:**
```bash
python libTARS_cli.py user keygen <user_id> [options]
```

**Arguments:**
- `user_id`: User identifier (e.g., 1001, 1002, 1003)

**Options:**
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-k, --key`: User key file (default: `config/user/user_{user_id}_key.json`)
- `-pk, --public-key`: User public key file (default: `config/user/user_{user_id}_pub.json`)
- `-d, --user-dir`: User key directory (default: `config/user`)

**Example:**
```bash
python libTARS_cli.py user keygen 1001 -p config/params.json -d config/user -k config/user/user_1001_key.json -pk config/user/user_1001_pub.json
```

**What it does:**
- Generates user's private key, public key, and PID
- Saves to key file and public key file
- **Warning**: Will overwrite existing user keys

### 2. Sign - Create Ring Signature

**Command:**
```bash
python libTARS_cli.py user sign <user_id> <message> <ring> [options]
```

**Arguments:**
- `user_id`: ID of the signing user
- `message`: Message to sign (file path or string)
- `ring`: Ring member IDs (comma-separated string, space-separated list, or file path)

**Options:**
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-k, --key`: User key file (default: `config/user/user_{user_id}_key.json`)
- `-d, --user-dir`: User key directory (default: `config/user`)
- `-e, --event`: Event field (default: "default")
- `-o, --output`: Signature output file

**Examples:**
```bash
# Sign with comma-separated ring
python libTARS_cli.py user sign 1001 temp/test_message.txt 1001,1002,1003 -p config/params.json -d config/user -o temp/test_signature.json

# Sign with space-separated ring
python libTARS_cli.py user sign 1001 temp/test_message.txt 1001 1002 1003 -p config/params.json -d config/user -o temp/test_signature.json

# Sign with ring from file
python libTARS_cli.py user sign 1001 temp/test_message.txt temp/ring.txt -p config/params.json -d config/user -o temp/test_signature.json
```

**What it does:**
- Creates anonymous ring signature
- Encrypts signer's PID for traceability
- Outputs signature to file or stdout

### 3. Verify - Verify Ring Signature

**Command:**
```bash
python libTARS_cli.py user verify <message> [options]
```

**Arguments:**
- `message`: Message to verify (file path or string)

**Options:**
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-d, --user-dir`: User key directory (default: `config/user`)
- `-i, --input`: Signature input file (required)

**Example:**
```bash
python libTARS_cli.py user verify temp/test_message.txt -p config/params.json -d config/user -i temp/test_signature.json
```

**What it does:**
- Verifies ring signature authenticity
- Checks that signature was created by a member of the specified ring
- Does not require user private keys (public verification)

## Tracer Commands

### 1. Partial Decrypt - Perform Partial Decryption

**Command:**
```bash
python libTARS_cli.py tracer partial_decrypt <tracer_id> [options]
```

**Arguments:**
- `tracer_id`: Tracer identifier (e.g., 1, 2, 3)

**Options:**
- `-i, --input`: Signature input file (required)
- `-k, --key`: Tracer key file (required)
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-o, --output`: Output partial decryption result file

**Example:**
```bash
python libTARS_cli.py tracer partial_decrypt 1 -p config/params.json -k config/tracer/tracer_1_key.json -i temp/test_signature.json -o temp/test_partial_decrypt_1.json
```

**What it does:**
- Performs partial decryption using tracer's key share
- Generates Schnorr proof for verification
- Outputs partial decryption result

### 2. Recover - Recover Signer PID

**Command:**
```bash
python libTARS_cli.py tracer recover [options]
```

**Options:**
- `-i, --input`: Signature input file (required)
- `-s, --shares`: Partial decryption result file list (required, comma-separated)
- `-p, --params`: System parameter file (default: `config/params.json`)
- `-o, --output`: Output PID file

**Example:**
```bash
python libTARS_cli.py tracer recover -p config/params.json -i temp/test_signature.json -s temp/test_partial_decrypt_1.json,temp/test_partial_decrypt_2.json -o temp/test_pid.txt
```

**What it does:**
- Combines multiple partial decryption results
- Recovers the original signer's PID
- Identifies the actual signer from the ring

## Complete Workflow Example

Here's a complete example workflow:

```bash
# 1. Setup system
python libTARS_cli.py kgc setup -p config/params.json -k config/kgc/key.json

# 2. Generate tracer keys
python libTARS_cli.py kgc tracerkeygen -p config/params.json -k config/kgc/key.json -o config/tracer/tracer_keys.json

# 3. Generate user keys
for uid in 1001 1002 1003; do
    python libTARS_cli.py user keygen $uid -p config/params.json -d config/user
done

# 4. Create test message
mkdir -p temp
echo "This is a test message for ring signature." > temp/test_message.txt

# 5. Create ring signature
python libTARS_cli.py user sign 1001 temp/test_message.txt 1001,1002,1003 -p config/params.json -d config/user -o temp/test_signature.json

# 6. Verify signature
python libTARS_cli.py user verify temp/test_message.txt -p config/params.json -d config/user -i temp/test_signature.json

# 7. Partial decryption by tracers
for tid in 1 2; do
    python libTARS_cli.py tracer partial_decrypt $tid -p config/params.json -k config/tracer/tracer_${tid}_key.json -i temp/test_signature.json -o temp/test_partial_decrypt_${tid}.json
done

# 8. Recover signer identity
python libTARS_cli.py tracer recover -p config/params.json -i temp/test_signature.json -s temp/test_partial_decrypt_1.json,temp/test_partial_decrypt_2.json -o temp/test_pid.txt
```

## File Formats

### Signature File Format
```json
{
  "PID_encryption": ["C1", "C2"],
  "PID_signature": ["T", "s"],
  "ring_user_ids": ["1001", "1002", "1003"],
  "event": "default"
}
```

### Partial Decryption Result Format
```json
{
  "x_i": 1,
  "s_share": "point_string",
  "proof": ["T", "s"],
  "tracer_id": 1
}
```

### User Key File Format
```json
{
  "user_id": "1001",
  "sk": 123456789,
  "pk": "point_string",
  "pid": "point_string"
}
```

### Tracer Key File Format
```json
{
  "tracer_id": 1,
  "x_i": 1,
  "pub_share": "point_string",
  "d_share": 987654321
}
```

## Important Notes

1. **Key Management**: Always backup your keys before overwriting them
2. **Threshold Tracing**: The number of tracers required for recovery is configured in system parameters
3. **File Paths**: Use absolute paths or ensure working directory is correct
4. **Error Handling**: Check file existence and permissions before running commands
5. **Security**: Keep private keys secure and never share them

## Troubleshooting

- **File not found errors**: Ensure all required files exist and paths are correct
- **Key mismatch errors**: Regenerate keys if system parameters have changed
- **Verification failures**: Check that all ring members' public keys are available
- **Decryption failures**: Ensure sufficient tracer shares are provided for threshold recovery
