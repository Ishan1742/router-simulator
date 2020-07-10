"""
Runner script for the router simulator
"""

import sys
import argparse

from router import Router


def parse_args() -> argparse.Namespace:
    """
    Command line interface commands for argument parser

    :return: return the prased arguments
    """
    parser = argparse.ArgumentParser(description='Router simulator using distance-vector routing protocol')
    parser.add_argument("--ip", help="Router IP address",
                        type=str, required=True)
    parser.add_argument("--update",
                        help="Router update sending time", type=int)
    parser.add_argument("--startup", help="Command input file")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    router = Router(args.ip, args.update, args.startup)
    router.run()
