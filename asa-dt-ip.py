#!/usr/bin/env python3
"""
asa_set_dt_ip.py — change the IP address on the DT interface (Ethernet1/9).

Reuses the serial console connection from asa-config-vpn.py (CiscoASA class),
so the same auth / factory-wizard / enable-mode handling applies. That file must
sit in the same directory as this one.

Environment variables:
  ASA_DT_IP         (required)  New IP address,        e.g. 192.168.20.30
  ASA_DT_NETMASK    (optional)  Dotted-decimal mask,   default 255.255.255.0
  ASA_DT_INTERFACE  (optional)  Hardware interface,    default Ethernet1/9
  ASA_DT_NAMEIF     (optional)  Expected nameif,       default DTOUT
  ASA_KNOWN_SECRET  (optional)  Enable password,       default Cisco123
  ASA_SECRET        (optional)  Overrides ASA_KNOWN_SECRET for auth

Usage:
  export ASA_DT_IP=192.168.20.45
  export ASA_DT_NETMASK=255.255.255.0
  ./asa_set_dt_ip.py                 # apply and save
  ./asa_set_dt_ip.py --dry-run       # print commands only, no serial connection
  ./asa_set_dt_ip.py --no-save       # apply but do not 'write memory'
"""

import argparse
import importlib.util
import ipaddress
import logging
import os
import re
import sys

# The VPN script is named with hyphens (asa-config-vpn.py), which is not a legal
# Python module name, so 'import asa_config_vpn' cannot reach it. Load it by
# file path from this script's own directory instead. The underscore spelling is
# kept as a fallback so the script keeps working if the file is renamed back.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_VPN_CANDIDATES = ['asa-config-vpn.py', 'asa_config_vpn.py']


def _load_vpn_module():
    for filename in _VPN_CANDIDATES:
        path = os.path.join(_SCRIPT_DIR, filename)
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location('asa_config_vpn', path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        # Register before exec so anything inside that looks itself up by name
        # (pickle, dataclasses, logging config) resolves correctly.
        sys.modules['asa_config_vpn'] = module
        spec.loader.exec_module(module)
        return module

    print(f"[ ERROR ] Could not find any of {', '.join(_VPN_CANDIDATES)} in "
          f"{_SCRIPT_DIR}. Keep this script in the same directory as the "
          f"ASA VPN script.")
    sys.exit(1)


_vpn = _load_vpn_module()

CiscoASA = _vpn.CiscoASA
Colors = _vpn.Colors
success = _vpn.success
error = _vpn.error
warn = _vpn.warn

DEFAULT_INTERFACE = 'Ethernet1/9'
DEFAULT_NAMEIF = 'DTOUT'
DEFAULT_NETMASK = '255.255.255.0'


def info(msg):
    print(f"{Colors.CYAN}[ INFO ]{Colors.RESET} {msg}")


def read_env():
    """Collect and validate the inputs from the environment."""
    ip_address = os.getenv('ASA_DT_IP')
    netmask = os.getenv('ASA_DT_NETMASK', DEFAULT_NETMASK)
    interface = os.getenv('ASA_DT_INTERFACE', DEFAULT_INTERFACE)
    nameif = os.getenv('ASA_DT_NAMEIF', DEFAULT_NAMEIF)

    if not ip_address:
        error("ASA_DT_IP is not set. Export it before running, e.g.\n"
              "         export ASA_DT_IP=192.168.20.45")
        sys.exit(1)

    try:
        addr = ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        error(f"ASA_DT_IP is not a valid IPv4 address: {ip_address}")
        sys.exit(1)

    try:
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        error(f"ASA_DT_NETMASK is not a valid dotted-decimal mask: {netmask}")
        sys.exit(1)

    # An ASA will accept these and then quietly black-hole the interface.
    if network.prefixlen < 31:
        if addr == network.network_address:
            error(f"{ip_address} is the network address of {network} — "
                  f"pick a host address.")
            sys.exit(1)
        if addr == network.broadcast_address:
            error(f"{ip_address} is the broadcast address of {network} — "
                  f"pick a host address.")
            sys.exit(1)

    if not re.match(r'^[A-Za-z]+\d+/\d+$', interface):
        error(f"ASA_DT_INTERFACE does not look like a hardware interface: {interface}")
        sys.exit(1)

    return {
        'ip_address': ip_address,
        'netmask': netmask,
        'interface': interface,
        'nameif': nameif,
        'network': str(network),
    }


def build_commands(settings):
    """The config-mode commands that change the address. Nothing else is touched."""
    return [
        f"interface {settings['interface']}",
        f" ip address {settings['ip_address']} {settings['netmask']}",
    ]


def show_interface(asa, interface):
    """Return the running-config block for the interface."""
    return asa.send_command(f'show running-config interface {interface}', timeout=10)


def current_ip(config_block):
    """Pull 'ip address A B' out of a running-config interface block."""
    match = re.search(r'^\s*ip address (\S+) (\S+)', config_block or '', re.MULTILINE)
    return (match.group(1), match.group(2)) if match else None


def main():
    parser = argparse.ArgumentParser(
        description="Change the IP address on the ASA DT interface (Ethernet1/9)."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the commands without connecting to the device")
    parser.add_argument("--no-save", action="store_true",
                        help="Apply the change but do not write to startup-config")
    parser.add_argument("--verbose", action="store_true",
                        help="Echo raw console output")
    args = parser.parse_args()

    settings = read_env()
    commands = build_commands(settings)

    print(f"\n{Colors.BOLD}DT interface address change{Colors.RESET}")
    print(f"  Interface : {settings['interface']} (expected nameif {settings['nameif']})")
    print(f"  New IP    : {settings['ip_address']} {settings['netmask']}  "
          f"[{settings['network']}]")

    if args.dry_run:
        print(f"\n{Colors.CYAN}{Colors.BOLD}--- DRY RUN MODE ---{Colors.RESET}")
        print("Commands to be sent:")
        print("-" * 40)
        print("  configure terminal")
        for cmd in commands:
            print(f"  {cmd}")
        print("  exit")
        if not args.no_save:
            print("  write memory")
        print("-" * 40)
        print(f"{Colors.YELLOW}No changes were made to the hardware.{Colors.RESET}")
        return 0

    asa = None
    try:
        asa = CiscoASA(verbose=args.verbose)
        if not asa.connect():
            error("Failed to connect to ASA")
            return 1

        before = show_interface(asa, settings['interface'])

        if not before or 'Invalid input' in before:
            error(f"Could not read {settings['interface']} from the running config. "
                  f"Check the interface name.")
            return 1

        if 'nameif' not in before:
            warn(f"{settings['interface']} has no nameif configured — the ASA will "
                 f"reject 'ip address' until one is set. Run the full "
                 f"asa-config-vpn.py first.")
            return 1

        existing = current_ip(before)
        if existing:
            info(f"Current address: {existing[0]} {existing[1]}")
            if existing == (settings['ip_address'], settings['netmask']):
                success("Interface already has the requested address — nothing to do.")
                return 0
        else:
            info("Interface currently has no IP address configured.")

        results = asa.send_config_commands(
            commands,
            description=f"Set {settings['interface']} to {settings['ip_address']}"
        )

        if results is None:
            error("Failed to send configuration commands")
            return 1

        after = show_interface(asa, settings['interface'])
        applied = current_ip(after)

        if applied == (settings['ip_address'], settings['netmask']):
            success(f"{settings['interface']} now has "
                    f"{applied[0]} {applied[1]}")
        else:
            error(f"Verification failed — device reports "
                  f"{applied if applied else 'no address'}")
            return 1

        if args.no_save:
            warn("Change is in the running config only. It will be lost on reload "
                 "(re-run without --no-save, or issue 'write memory' manually).")
        else:
            if asa.save_config():
                success("Saved to startup-config")
            else:
                warn("Address applied but the startup-config save failed — "
                     "the change will not survive a reload.")
                return 1

        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ COMPLETE{Colors.RESET}")
        return 0

    except KeyboardInterrupt:
        warn("Cancelled by user — the interface may be partially configured.")
        return 130
    except Exception as e:
        error(f"Failed: {e}")
        logging.error(f"DT IP change failed: {e}")
        return 1
    finally:
        if asa:
            asa.disconnect()


if __name__ == "__main__":
    sys.exit(main())
