#!/usr/bin/env python3

import base64
import struct
import argparse
from Crypto.Cipher import ARC4
import logging
import sys

logging.basicConfig(level=logging.INFO)

# Language and meta mappings from Empire documentation https://github.com/BC-SECURITY/Empire/blob/main/empire/server/common/packets.py
LANGUAGE_IDS = {
    0: "NONE",
    1: "POWERSHELL",
    2: "PYTHON",
    3: "CSHARP",
}
META_IDS = {
    0: "NONE",
    1: "STAGE0",
    2: "STAGE1",
    3: "STAGE2",
    4: "TASKING_REQUEST",
    5: "RESULT_POST",
    6: "SERVER_RESPONSE",
}

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def parse_session_info(session_info):
    try:
        session_id = session_info[:8].decode('utf-8')
        lang, meta = struct.unpack('<BB', session_info[8:10])
        extra = session_info[10:12]
        length = struct.unpack('<I', session_info[12:16])[0]

        # Map lang and meta to descriptive values
        lang_description = LANGUAGE_IDS.get(lang, 'Unknown')
        meta_description = META_IDS.get(meta, 'Unknown')

        print("\n[+] Decrypted Cookie Information:")
        print("=============================")
        print(f"Session ID : {session_id}")
        print(f"Language   : {lang} ({lang_description})")
        print(f"Meta       : {meta} ({meta_description})")
        print(f"Extra Data : {extra.hex()}")
        print(f"Data Length: {length}\n")

    except Exception as e:
        logging.error(f"[x] Error parsing session info: {e}")
        sys.exit(1)

def process_cookie(cookie_value, staging_key):
    try:
        cookie_data = base64.b64decode(cookie_value)
        logging.debug(f"[i] Cookie Data (Base64-decoded): {cookie_data.hex()}")

        # Extract RC4 IV and construct RC4 key
        rc4_iv = cookie_data[:4]
        rc4_key = rc4_iv + staging_key.encode()
        logging.debug(f"[i] RC4 Key: {rc4_key.hex()}")

        # RC4-decrypt the rest of the cookie data
        rc4_encrypted_data = cookie_data[4:]
        decrypted_cookie_data = rc4_decrypt(rc4_key, rc4_encrypted_data)
        logging.debug(f"[i] Decrypted Cookie Data: {decrypted_cookie_data.hex()}")

        parse_session_info(decrypted_cookie_data)

    except Exception as e:
        logging.error(f"[x] Failed to process cookie: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='Empire C2 Cookie Decryption Script (SanityCheck)',
        epilog='Example usage: python decrypt_cookie.py --key "StagingKey" --cookie "CookieValue"'
    )
    parser.add_argument(
        '--key', '-k', required=True,
        help='Staging key used for RC4 decryption'
    )
    parser.add_argument(
        '--cookie', '-c', required=True,
        help='Base64-encoded cookie value to decrypt'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output for debugging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    staging_key = args.key
    cookie_value = args.cookie

    process_cookie(cookie_value, staging_key)

if __name__ == "__main__":
    main()
