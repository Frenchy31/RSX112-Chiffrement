#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hex Writer

Run with command-line argument "-h" to display the online help.

Nicolas Pioch, 31 Mar 2012
$Id$
"""

import argparse


def main():
    parser = argparse.ArgumentParser(
        description='Write a binary file from its hexadecimal contents.')
    parser.add_argument('-i', '--infile',
                        help='Input file name',
                        required=True,
                        type=argparse.FileType('r'))
    parser.add_argument('-o', '--outfile',
                        help='Output file name',
                        required=True,
                        type=argparse.FileType('wb'))
    args = parser.parse_args()

    for line in args.infile:
        for token in line.split():
            token = token.strip(',.')
            assert token[0:2] == "0x", "Unexpected token found: \"%s\"" % token
            args.outfile.write(bytes([int(token, 16)]))

    args.infile.close()
    args.outfile.close()


if __name__ == "__main__":
    main()
