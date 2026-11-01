#!/usr/bin/env python3
"""Debug argparse issue."""
from argparse import ArgumentParser

parser = ArgumentParser(prog='hunter')
subparsers = parser.add_subparsers(dest='command')
recon_parser = subparsers.add_parser('recon')
recon_sub = recon_parser.add_subparsers(dest='recon_action')
recon_sub.add_parser('dns')
recon_sub.add_parser('http')
recon_sub.add_parser('assets')
recon_sub.add_parser('status')
recon_parser.add_argument('target', nargs='?', default='')
recon_parser.add_argument('url', nargs='?', default='')

try:
    args = parser.parse_args(['recon', 'dns', 'example.com'])
    print(f"command={args.command} recon_action={args.recon_action} target={args.target} url={args.url}")
except SystemExit as e:
    print(f"Failed with exit code {e.code}")

# Try without url arg
parser2 = ArgumentParser(prog='hunter')
subparsers2 = parser2.add_subparsers(dest='command')
recon_parser2 = subparsers2.add_parser('recon')
recon_sub2 = recon_parser2.add_subparsers(dest='recon_action')
recon_sub2.add_parser('dns')
recon_parser2.add_argument('target', nargs='?', default='')
try:
    args2 = parser2.parse_args(['recon', 'dns', 'example.com'])
    print(f"Without url: command={args2.command} recon_action={args2.recon_action} target={args2.target}")
except SystemExit as e:
    print(f"Without url failed: {e.code}")
