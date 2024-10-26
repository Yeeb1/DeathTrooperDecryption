#!/usr/bin/env python3

import argparse
import logging
import struct
import hmac
import hashlib
import base64
from Crypto.Cipher import ARC4, AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

logging.basicConfig(level=logging.INFO)

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    logging.debug(f"[i] RC4 Key: {key.hex()}")
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(data)
    logging.debug(f"[i] RC4 Decrypted data: {decrypted_data.hex()}")
    return decrypted_data

def aes_decrypt_with_hmac(key, data):
    try:
        IV = data[:16]
        ciphertext_and_hmac = data[16:]

        logging.debug(f"[i] IV ({len(IV)} bytes): {IV.hex()}")

        if len(ciphertext_and_hmac) > 10:
            hmac_signature = ciphertext_and_hmac[-10:]
            ciphertext = ciphertext_and_hmac[:-10]
        else:
            logging.error("[x] Not enough data for HMAC signature.")
            return None

        logging.debug(f"[i] Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
        logging.debug(f"[i] HMAC Signature ({len(hmac_signature)} bytes): {hmac_signature.hex()}")

        expected_hmac = hmac.new(key, IV + ciphertext, digestmod=hashlib.sha256).digest()[:10]
        if not hmac.compare_digest(hmac_signature, expected_hmac):
            logging.error("[x] HMAC verification failed.")
            return None

        if len(ciphertext) % 16 != 0:
            logging.error("[x] Ciphertext length is not a multiple of block size after removing HMAC.")
            return None

        cipher = AES.new(key, AES.MODE_CBC, IV)
        decrypted_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_data, AES.block_size)
        return plaintext
    except Exception as e:
        logging.error(f"[x] Error during AES decryption: {e}")
        return None

def interpret_packet_structure(data: bytes):
    try:
        session_id = data[:8].decode('ascii')
        lang, meta, extra, length = struct.unpack('<BBHI', data[8:16])
        logging.info(f"SessionID: {session_id}")
        logging.info(f"Lang: {lang}")
        logging.info(f"Meta: {meta}")
        logging.info(f"Extra: {extra}")
        logging.info(f"Length: {length}")
        return {
            'SessionID': session_id,
            'Lang': lang,
            'Meta': meta,
            'Extra': extra,
            'Length': length,
        }
    except (UnicodeDecodeError, struct.error) as e:
        logging.error(f"[x] Failed to interpret packet: {e}")
        return None

def main(args):
    try:
        with open(args.privkey, 'rb') as key_file:
            private_key_pem = key_file.read()

        # Load the hex content from 'stage1_response.bin' and convert it to bytes
        with open(args.stage1_response, 'r') as f:
            hex_content = f.read().strip().replace('\n', '').replace('\r', '').replace(' ', '')
            encrypted_payload = bytes.fromhex(hex_content)

        # Decrypt the RSA-encrypted payload to get nonce and session key
        private_key = RSA.importKey(private_key_pem)
        cipher_rsa = PKCS1_v1_5.new(private_key)
        decrypted_payload = cipher_rsa.decrypt(encrypted_payload, None)

        # Extract nonce and session key
        nonce = decrypted_payload[:16]
        session_key = decrypted_payload[16:]

        logging.info(f"[+] Nonce: {nonce.hex()}")
        logging.info(f"[+] Session Key: {session_key.hex()}")

        # Process the Stage 2 data
        with open(args.stage2_request, 'r') as f:
            hex_content = f.read().strip().replace('\n', '').replace('\r', '').replace(' ', '')
            enc_data = bytes.fromhex(hex_content)
            logging.debug(f"[i] Hex decoded data (initial): {enc_data.hex()}")

        total_data_length = len(enc_data)
        logging.debug(f"[i] Total data length: {total_data_length} bytes")

        # RC4 decryption of the session information
        rc4_key = enc_data[:4] + args.staging_key.encode()
        session_info_encrypted = enc_data[4:20]
        session_info = rc4_decrypt(rc4_key, session_info_encrypted)
        logging.debug(f"[i] RC4 decrypted session info: {session_info.hex()}")

        # Interpret the decrypted packet structure
        packet_info = interpret_packet_structure(session_info)
        if packet_info:
            length = packet_info['Length']
            logging.debug(f"[i] Length extracted from packet: {length} bytes")

            expected_total_length = 4 + 16 + length
            if total_data_length < expected_total_length:
                logging.error(f"[x] Data is incomplete. Expected at least {expected_total_length} bytes, but got {total_data_length} bytes.")
                return

            aes_encrypted_data = enc_data[20:20+length]
            logging.debug(f"[i] AES Encrypted Data: {aes_encrypted_data.hex()}")

            decrypted_payload = aes_decrypt_with_hmac(session_key, aes_encrypted_data)
            if decrypted_payload:
                # Strip the first 12 bytes from the decrypted payload
                base64_payload = decrypted_payload[12:]
                logging.debug(f"[i] Payload after stripping first 12 bytes: {base64_payload.hex()}")

                try:
                    decoded_payload = base64.b64decode(base64_payload)
                    logging.info(f"[+] Base64-decoded Payload:\n{decoded_payload}")

                    if args.output:
                        with open(args.output, 'wb') as out_file:
                            out_file.write(decoded_payload)
                        logging.info(f"[+] Decoded payload saved to: {args.output}")

                except base64.binascii.Error as e:
                    logging.error(f"[x] Base64 decoding failed: {e}")
            else:
                logging.error("[x] AES decryption failed.")
        else:
            logging.error("[x] No valid information extracted from the payload.")
    except Exception as e:
        logging.error(f"[x] An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Decrypt agent data sent to the C2 server',
        epilog='Example usage: python stage2_decrypt_agentdata.py --privkey <private_key> --stage1_response <file> --stage2_request <file> --staging_key <key>'
    )
    parser.add_argument(
        '--privkey', '-p', required=True,
        help='Path to the private RSA key file (PEM format)'
    )
    parser.add_argument(
        '--stage1_response', '-s1', required=True,
        help='Path to the stage1 RSA-encrypted response file (hex encoded)'
    )
    parser.add_argument(
        '--stage2_request', '-s2', required=True,
        help='Path to the stage2 request file (hex encoded)'
    )
    parser.add_argument(
        '--staging_key', '-k', required=True,
        help='Staging key used for RC4 decryption'
    )
    parser.add_argument(
        '--output', '-o', default='decoded_payload.txt',
        help='Output filename to save the decoded payload (default: decoded_payload.txt)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output for debugging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    main(args)
