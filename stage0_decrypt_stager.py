#!/usr/bin/env python3

import argparse
import struct
import logging
from Crypto.Cipher import ARC4
import sys

logging.basicConfig(level=logging.INFO)

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def main():
    parser = argparse.ArgumentParser(
        description='Empire C2 Stager Decryption Script',
        epilog='Example usage: python decrypt_stager.py --key "StagingKey" --file "hex_data.txt" --output "decrypted_payload.ps1"'
    )
    parser.add_argument(
        '--key', '-k', required=True,
        help='Session key used for RC4 decryption'
    )
    parser.add_argument(
        '--file', '-f', required=True,
        help='Path to the file containing the hex data stream'
    )
    parser.add_argument(
        '--output', '-o', default='decrypted_payload.txt',
        help='Output filename to save the decrypted payload (default: decrypted_payload.txt)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output for debugging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    key = args.key
    try:
        with open(args.file, 'r') as f:
            hex_data = f.read().strip().replace('\n', '').replace('\r', '').replace(' ', '')
    except Exception as e:
        logging.error(f"[x] Failed to read hex data from file: {e}")
        sys.exit(1)

    try:
        enc_data = bytes.fromhex(hex_data)
        logging.debug(f"[i] Hex decoded data: {enc_data.hex()}")

        # Use RC4 to decrypt the data. RC4 key is the first 4 bytes of enc_data + session key
        rc4_iv = enc_data[:4]
        rc4_key = rc4_iv + key.encode()
        logging.debug(f"[i] RC4 Key: {rc4_key.hex()}")

        decrypted_data = rc4_decrypt(rc4_key, enc_data[4:])  # Decrypt the rest of the data
        logging.debug(f"[i] RC4 decrypted data: {decrypted_data.hex()}")

        output_filename = args.output
        with open(output_filename, 'wb') as out_file:
            out_file.write(decrypted_data)
        print(f"[+] Decrypted stager saved to: {output_filename}")

        try:
            decrypted_text = decrypted_data.decode('utf-8', errors='replace')
            print("\n[+] Decrypted Stager Payload:\n")
            print(decrypted_text)
        except UnicodeDecodeError:
            logging.warning("[x] Decrypted data is not valid UTF-8 text.")

    except Exception as e:
        logging.error(f"[x] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
