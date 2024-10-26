#!/usr/bin/env python3

import argparse
import base64
import logging
from xml.etree import ElementTree

logging.basicConfig(level=logging.INFO)

def extract_modulus_from_xml(rsa_xml):
    try:
        root = ElementTree.fromstring(rsa_xml)
        modulus_b64 = root.findtext('Modulus').strip()

        modulus_bytes = base64.b64decode(modulus_b64)

        modulus_int = int.from_bytes(modulus_bytes, byteorder='big')

        print("\n[+] Modulus as decimal integer:")
        print("==================")
        print(modulus_int)

    except Exception as e:
        logging.error(f"[x] Failed to extract modulus from XML: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Extract and print modulus from RSAKeyValue XML file.',
        epilog='Example usage: python extract_modulus.py --file rsa_key.xml'
    )
    parser.add_argument(
        '--file', '-f', required=True,
        help='Path to the RSAKeyValue XML file'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output for debugging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        with open(args.file, 'r') as f:
            rsa_xml = f.read()
        logging.debug(f"[i] RSA XML Content: {rsa_xml}")
    except Exception as e:
        logging.error(f"[x] Failed to read RSA XML file: {e}")
        return

    extract_modulus_from_xml(rsa_xml)

if __name__ == "__main__":
    main()
