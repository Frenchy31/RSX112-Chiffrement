#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cipher Factory

Run with command-line argument "-h" to display the online help.

Aubin Puyoou, 7 Nov 2021
$Id$
"""

import argparse


def init_rc4(keyfile):
    s = []
    k = []
    for i in range(0, 256):
        s.append(i)
        k.append(keyfile[i % len(keyfile)])
    j = 0
    for i in range(0, 256):
        j = (j + s[i] + k[i]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def cipher_rc4(infile, keyfile, outfile, skip_bytes, debug):
    print('Début du chiffrement RC4.')
    s = init_rc4(keyfile)
    i = 0
    j = 0
    cipher_bytes_list = []
    if skip_bytes:
        for i in range(0, skip_bytes):
            cipher_bytes_list.append(infile[i])
    for m in range(skip_bytes, len(infile)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        cipher_byte = s[(s[i] + s[j]) % 256]
        cipher_bytes_list.append(cipher_byte ^ infile[m])
    print('Ecriture dans le fichier.')
    outfile.write(bytes(cipher_bytes_list))
    print('Fin chiffrement.')


def main():
    parser = argparse.ArgumentParser(
        description='Cipher a binary file using the argument algorithm')
    parser.add_argument('-d', '--debug',
                        help='Enable debug diagnostics',
                        required=False,
                        action='store_true')
    parser.add_argument('-s', '--skip-bytes',
                        required=False,
                        help='Number of bytes to copy unmodified (default: 0)',
                        default=0,
                        type=int)
    parser.add_argument('-c', '--cipher',
                        help='Cipher to use',
                        required=False,
                        default='rc4',
                        choices=['rc4', 'aes-ecb', 'aes-cbc', 'aes-ctr'])
    parser.add_argument('--decrypt',
                        help='Decrypt (default is to encrypt instead)',
                        required=False,
                        action='store_true')
    parser.add_argument('-k', '--keyfile',
                        help='Key file name to use',
                        required=True,
                        type=argparse.FileType('rb'))
    parser.add_argument('--iv',
                        help='Initialization Vector file name (CBC only)',
                        required=False,
                        type=argparse.FileType('r'))
    parser.add_argument('-i', '--infile',
                        help='Input file name',
                        required=True,
                        type=argparse.FileType('rb'))
    parser.add_argument('-o', '--outfile',
                        help='Output file name',
                        required=True,
                        type=argparse.FileType('wb'))
    args = parser.parse_args()

    if args.cipher == 'rc4':
        cipher_rc4(args.infile.read(), args.keyfile.read(), args.outfile, args.skip_bytes, args.debug)

    args.infile.close()
    args.keyfile.close()
    args.outfile.close()


if __name__ == "__main__":
    main()
