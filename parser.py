import argparse


def parse_cli_args():
    parser = argparse.ArgumentParser(description='CryptoCore - A tool for file encryption and decryption.')

    parser.add_argument('-algorithm', type=str, required=True, choices=['aes'],
                        help='Cipher algorithm (only aes supported)')

    parser.add_argument('-mode', type=str, required=True, choices=['ecb'],
                        help='Mode of operation (only ecb supported)')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-encrypt', action='store_true', help='Perform encryption')
    group.add_argument('-decrypt', action='store_true', help='Perform decryption')

    parser.add_argument('-key', type=str, required=True,
                        help='Encryption key as a hexadecimal string (e.g., @001122...)')
    parser.add_argument('-input', type=str, required=True, help='Path to the input file')

    parser.add_argument('-output', type=str, help='Path to the output file')

    args = parser.parse_args()

    if not args.key.startswith('@'):
        raise ValueError("Key must start with '@' followed by a hex string.")

    key_hex = args.key[1:]

    if len(key_hex) != 32:
        raise ValueError("Key must be 16 bytes long (32 hex characters).")

    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Key contains invalid hexadecimal characters.")

    if args.output is None:
        args.output = derive_output_filename(args.input, args.encrypt)

    return args


def derive_output_filename(input_path, is_encrypt):
    if is_encrypt:
        return input_path + '.enc'
    else:
        if input_path.endswith('.enc'):
            return input_path[:-4] + '.dec'
        else:
            return input_path + '.dec'