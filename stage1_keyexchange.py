#!/usr/bin/env python3

import argparse
import logging
import struct
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys
import base64
import xml.dom.minidom

logging.basicConfig(level=logging.INFO)

LANGUAGE_DESCRIPTIONS = {
    0: "NONE",
    1: "POWERSHELL",
    2: "PYTHON",
    3: "CSHARP",
}
META_DESCRIPTIONS = {
    2: 'Beacon/Check-in',
    4: 'Tasking Request',
    5: 'Result Post',
    6: 'Server Response',
}

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    logging.debug(f"[i] RC4 Key: {key.hex()}")
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(data)
    logging.debug(f"[i] RC4 Decrypted data: {decrypted_data.hex()}")
    return decrypted_data

def aes_decrypt(key, data):
    try:
        backend = default_backend()
        IV = data[:16]
        ciphertext = data[16:]
        if len(ciphertext) % 16 != 0:
            logging.error("[x] Ciphertext length is not a multiple of block size.")
            return None
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        try:
            return unpad(decrypted_data, 16)
        except ValueError as e:
            logging.error(f"[x] Error during unpadding: {e}")
            return None
    except Exception as e:
        logging.error(f"[x] Error during AES decryption: {e}")
        return None

def interpret_packet_structure(data: bytes):
    try:
        session_id = data[:8].decode('ascii')
        lang, meta = struct.unpack('<BB', data[8:10])
        extra = data[10:12]
        length = struct.unpack('<I', data[12:16])[0]

        meta_description = META_DESCRIPTIONS.get(meta, 'Unknown')
        lang_description = LANGUAGE_DESCRIPTIONS.get(lang, 'Unknown')

        print("\n[+] Session Information:")
        print("====================")
        print(f"Session ID    : {session_id}")
        print(f"Language      : {lang} ({lang_description})")
        print(f"Meta          : {meta} ({meta_description})")
        print(f"Extra         : {extra.hex()}")
        print(f"Data Length   : {length}\n")

        return {
            'SessionID': session_id,
            'Lang': lang,
            'Meta': meta,
            'Extra': extra.hex(),
            'Length': length,
        }
    except (UnicodeDecodeError, struct.error) as e:
        logging.error(f"[x] Failed to interpret packet: {e}")
        return None

def extract_rsa_key(decrypted_payload):
    try:
        payload_str = decrypted_payload.decode('utf-8', errors='ignore')
        start = payload_str.find('<RSAKeyValue>')
        end = payload_str.find('</RSAKeyValue>')
        if start != -1 and end != -1:
            rsa_key_value = payload_str[start:end+14]  
            print("\n[+] RSA Key XML:")
            print("==============")
            dom = xml.dom.minidom.parseString(rsa_key_value)
            pretty_rsa_key_value = dom.toprettyxml()
            print(pretty_rsa_key_value)

            modulus_start = rsa_key_value.find('<Modulus>')
            modulus_end = rsa_key_value.find('</Modulus>')
            if modulus_start != -1 and modulus_end != -1:
                modulus_b64 = rsa_key_value[modulus_start+9:modulus_end]
                modulus_bytes = base64.b64decode(modulus_b64)
                modulus_int = int.from_bytes(modulus_bytes, byteorder='big')
                print("\n[+] Modulus as Integer:")
                print("===================")
                print(modulus_int)
            else:
                print("[x] Modulus not found in RSA Key Value.")
        else:
            print("[x] RSA Key Value not found in the decrypted payload.")
    except Exception as e:
        logging.error(f"[x] Error extracting RSA key: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Empire C2 Stage1 Key Exchange Decryption Script',
        epilog='Example usage: python decrypt_stage1.py --key "StagingKey" --file "hex_data.txt"'
    )
    parser.add_argument(
        '--key', '-k', required=True,
        help='Staging key used for RC4 and AES decryption'
    )
    parser.add_argument(
        '--file', '-f', required=True,
        help='Path to the file containing the hex data stream'
    )
    parser.add_argument(
        '--output', '-o', default='decrypted_RSA.xml',
        help='Output filename to save the decrypted payload (default: decrypted_RSA.xml)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output for debugging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    hex_data_file = args.file
    staging_key_str = args.key

    try:
        with open(hex_data_file, 'r') as f:
            hex_data = f.read().strip().replace('\n', '').replace('\r', '').replace(' ', '')
    except Exception as e:
        logging.error(f"[x] Failed to read hex data from file: {e}")
        sys.exit(1)

    try:
        enc_data = bytes.fromhex(hex_data)
        logging.debug(f"[i] Hex decoded data (initial): {enc_data.hex()}")

        total_data_length = len(enc_data)
        logging.debug(f"[i] Total data length: {total_data_length} bytes")

        rc4_iv = enc_data[:4]
        rc4_key = rc4_iv + staging_key_str.encode()
        logging.debug(f"[i] RC4 Key: {rc4_key.hex()}")

        session_info_encrypted = enc_data[4:20]
        session_info = rc4_decrypt(rc4_key, session_info_encrypted)
        logging.debug(f"[i] RC4 decrypted session info: {session_info.hex()}")

        packet_info = interpret_packet_structure(session_info)
        if packet_info:
            length = packet_info['Length']
            expected_total_length = 4 + 16 + length 
            if total_data_length < expected_total_length:
                logging.error(f"[x] Data is incomplete. Expected at least {expected_total_length} bytes, but got {total_data_length} bytes.")
                return

            aes_encrypted_data = enc_data[20:20+length]
            logging.debug(f"[i] AES Encrypted Data Length: {len(aes_encrypted_data)} bytes")
            logging.debug(f"[i] AES Encrypted Data: {aes_encrypted_data.hex()}")

            IV = aes_encrypted_data[:16]
            ciphertext_and_hmac = aes_encrypted_data[16:]

            if len(ciphertext_and_hmac) > 10:
                hmac_signature = ciphertext_and_hmac[-10:]
                ciphertext = ciphertext_and_hmac[:-10]
                logging.debug(f"[i] HMAC Signature: {hmac_signature.hex()}")
            else:
                logging.error("[x] Not enough data for HMAC signature.")
                return

            if len(ciphertext) % 16 != 0:
                logging.error("[x] Ciphertext length is not a multiple of block size after removing HMAC.")
                return

            aes_key = staging_key_str.encode('UTF-8')
            logging.debug(f"[i] AES Key (staging key): {aes_key.hex()}")

            decrypted_payload = aes_decrypt(aes_key, IV + ciphertext)

            if decrypted_payload:
                output_filename = args.output
                with open(output_filename, 'wb') as out_file:
                    out_file.write(decrypted_payload)
                print(f"[+] Decrypted payload saved to: {output_filename}")

                print("\n[+] Decrypted Payload:")
                print("==================")
                print(decrypted_payload.decode('utf-8', errors='ignore'))

                extract_rsa_key(decrypted_payload)
            else:
                logging.error("[x] AES decryption failed.")
        else:
            logging.error("[x] No valid information extracted from the payload.")
    except Exception as e:
        logging.error(f"[x] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
