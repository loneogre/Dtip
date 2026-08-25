#!/usr/bin/env python3
"""
asa_set_dt_ip.py — change the IP address on the DT interface (Ethernet1/9)
and keep the matching 'object network DTIP' subnet in step with it.

Reuses the serial console connection from asa-config-vpn.py (CiscoASA class),
so the same auth / factory-wizard / enable-mode handling applies. That file must
sit in the same directory as this one.

Environment variables:
  ASA_DT_IP         (required)  New IP address,        e.g. 192.168.20.30
  ASA_DT_NETMASK    (optional)  Dotted-decimal mask,   default 255.255.255.0
  ASA_DT_INTERFACE  (optional)  Hardware interface,    default Ethernet1/9
  ASA_DT_NAMEIF     (optional)  Expected nameif,       default DTOUT
  ASA_DT_OBJECT     (optional)  Network object name,   default DTIP
  ASA_KNOWN_SECRET  (optional)  Enable password,       default Cisco123
  ASA_SECRET        (optional)  Overrides ASA_KNOWN_SECRET for auth

The object subnet is derived from ASA_DT_IP + ASA_DT_NETMASK — e.g.
192.168.20.45/255.255.255.0 gives 'subnet 192.168.20.0 255.255.255.0'.

Usage:
  export ASA_DT_IP=192.168.20.45
  export ASA_DT_NETMASK=255.255.255.0
  ./asa_set_dt_ip.py                 # apply both and save
  ./asa_set_dt_ip.py --dry-run       # print commands only, no serial connection
  ./asa_set_dt_ip.py --no-save       # apply but do not 'write memory'
  ./asa_set_dt_ip.py --skip-object   # interface only, leave the object alone
  ./asa_set_dt_ip.py --object-only   # object only, leave the interface alone
"""

import argparse
import importlib.util
import ipaddress
import logging
import os
import re
import sys
import time

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
DEFAULT_OBJECT = 'DTIP'


def info(msg):
    print(f"{Colors.CYAN}[ INFO ]{Colors.RESET} {msg}")


# ---------------------------------------------------------------------------
# Session handling
#
# 'console timeout 2' logs the console session out after two minutes idle and
# drops it from enable mode back to user EXEC ('hostname>'). Two consequences
# the shared readers in asa-config-vpn.py do not survive:
#
#   1. The logout injects an UNSOLICITED '>' prompt into the receive buffer.
#      _read_password_response() stops on any trailing [#>], so the read that
#      should have caught 'Password:' returns on that stale prompt instead,
#      the 'password' test fails, and enable is silently abandoned. Worse,
#      _try_serial_connection() ignores the return value of
#      _serial_enter_enable_mode(), so connect() still reports success and
#      every later command is issued at '>' where it is rejected.
#
#   2. The logout resets terminal settings, so 'terminal pager 0' is undone
#      and 'show running-config ...' starts paging on <--- More --->, which
#      the readers wait out until they time out.
#
# The helpers below read with explicit expect-patterns instead of "any prompt",
# and always drain stale input first, so a mid-run logout is detected and
# recovered from rather than mistaken for the reply to the current command.
# ---------------------------------------------------------------------------

ENABLE_PROMPT_RE = re.compile(r'(?m)^[\w.\-]+(?:\([\w\-]+\))?#\s*$')
USER_PROMPT_RE = re.compile(r'(?m)^[\w.\-]+>\s*$')
PASSWORD_RE = re.compile(r'(?i)password:\s*$')
USERNAME_RE = re.compile(r'(?i)username:\s*$')
DENIED_RE = re.compile(r'(?i)(access denied|invalid password|bad password)')


def drain(asa):
    """Discard anything left in the receive buffer from a previous command."""
    try:
        if asa.serial_port and asa.serial_port.in_waiting:
            asa.serial_port.reset_input_buffer()
    except Exception as e:
        logging.debug(f"Buffer drain failed: {e}")


def write_line(asa, text):
    asa.serial_port.write((text + '\r').encode('utf-8'))
    asa.serial_port.flush()


def read_for(asa, patterns, timeout=10):
    """
    Read until one of (name, compiled_pattern) matches. Returns (name, buffer),
    or (None, buffer) on timeout. The buffer starts empty on every call, so a
    match can only come from output produced after this call began.
    """
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if asa.serial_port.in_waiting:
            buf += asa.serial_port.read(
                asa.serial_port.in_waiting).decode('utf-8', errors='ignore')
            if asa.verbose:
                print(buf[-200:], end='', flush=True)
            for name, pattern in patterns:
                if pattern.search(buf):
                    return name, buf
        time.sleep(0.05)
    return None, buf


def ensure_enable(asa, secret):
    """
    Guarantee the session is at an enable ('#') prompt, re-authenticating if a
    console timeout has dropped it back to '>'. Safe to call repeatedly.
    """
    drain(asa)
    write_line(asa, '')

    state, buf = read_for(
        asa,
        [('enable', ENABLE_PROMPT_RE), ('user', USER_PROMPT_RE),
         ('password', PASSWORD_RE), ('username', USERNAME_RE)],
        timeout=5
    )

    if state == 'enable':
        return True

    if state == 'username':
        error("The console is behind AAA authentication (Username: prompt). "
              "This script only handles the enable password — log in manually "
              "or disable 'aaa authentication serial console'.")
        return False

    if state is None:
        error(f"No prompt from the console within 5s. Last bytes: "
              f"{buf.strip()[-80:]!r}")
        return False

    # At '>' (or straight at a Password: prompt after a logout).
    if state == 'user':
        info("Session is at the user EXEC prompt — re-entering enable mode.")
        drain(asa)
        write_line(asa, 'enable')
        state, buf = read_for(
            asa,
            [('password', PASSWORD_RE), ('enable', ENABLE_PROMPT_RE)],
            timeout=10
        )
        if state == 'enable':
            restore_terminal(asa)
            return True
        if state is None:
            error("No 'Password:' prompt after 'enable'.")
            return False

    write_line(asa, secret)
    state, buf = read_for(
        asa,
        [('enable', ENABLE_PROMPT_RE), ('denied', DENIED_RE),
         ('password', PASSWORD_RE), ('user', USER_PROMPT_RE)],
        timeout=10
    )

    if state == 'enable':
        success("Re-entered enable mode.")
        restore_terminal(asa)
        return True

    error("Enable authentication failed — check ASA_SECRET / ASA_KNOWN_SECRET.")
    return False


def restore_terminal(asa):
    """Re-apply pager/width, which a console logout resets."""
    for cmd in ('terminal pager 0', 'terminal width 200'):
        drain(asa)
        write_line(asa, cmd)
        read_for(asa, [('enable', ENABLE_PROMPT_RE)], timeout=5)


def console_timeout_value(asa):
    """Return the configured 'console timeout' in minutes, or None."""
    output = asa.send_command('show running-config | include console timeout',
                              timeout=10)
    match = re.search(r'console timeout (\d+)', output or '')
    return int(match.group(1)) if match else None


def read_env():
    """Collect and validate the inputs from the environment."""
    ip_address = os.getenv('ASA_DT_IP')
    netmask = os.getenv('ASA_DT_NETMASK', DEFAULT_NETMASK)
    interface = os.getenv('ASA_DT_INTERFACE', DEFAULT_INTERFACE)
    nameif = os.getenv('ASA_DT_NAMEIF', DEFAULT_NAMEIF)
    object_name = os.getenv('ASA_DT_OBJECT', DEFAULT_OBJECT)

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

    if not re.match(r'^[A-Za-z0-9_.\-]{1,64}$', object_name):
        error(f"ASA_DT_OBJECT is not a valid object name: {object_name}")
        sys.exit(1)

    return {
        'ip_address': ip_address,
        'netmask': netmask,
        'interface': interface,
        'nameif': nameif,
        'network': str(network),
        'object_name': object_name,
        # The object holds the SUBNET the DT address sits in, not the host
        # address, so it is derived from the network the new IP falls in.
        'subnet': str(network.network_address),
        'subnet_mask': str(network.netmask),
    }


def build_interface_commands(settings):
    """Config-mode commands that change the interface address. Nothing else."""
    return [
        f"interface {settings['interface']}",
        f" ip address {settings['ip_address']} {settings['netmask']}",
    ]


def build_object_commands(settings):
    """
    Config-mode commands that repoint the network object at the new subnet.

    Re-issuing 'subnet' inside an existing object network overwrites the
    previous value, so no 'no subnet' is needed. Any NAT or ACL rule that
    references the object picks up the new value automatically.
    """
    return [
        f"object network {settings['object_name']}",
        f" subnet {settings['subnet']} {settings['subnet_mask']}",
    ]


def show_interface(asa, interface):
    """Return the running-config block for the interface."""
    return asa.send_command(f'show running-config interface {interface}', timeout=10)


def current_ip(config_block):
    """Pull 'ip address A B' out of a running-config interface block."""
    match = re.search(r'^\s*ip address (\S+) (\S+)', config_block or '', re.MULTILINE)
    return (match.group(1), match.group(2)) if match else None


def show_object(asa, object_name):
    """Return the running-config block for the network object."""
    return asa.send_command(f'show running-config object id {object_name}', timeout=10)


def current_subnet(config_block):
    """Pull 'subnet A B' out of a running-config object block."""
    match = re.search(r'^\s*subnet (\S+) (\S+)', config_block or '', re.MULTILINE)
    return (match.group(1), match.group(2)) if match else None


def object_body_type(config_block):
    """
    Report what the object currently holds: 'subnet', 'host', 'range', 'fqdn'
    or None. Overwriting a host object with a subnet is legal on the ASA but
    almost certainly means the wrong object name was passed in.
    """
    match = re.search(r'^\s*(subnet|host|range|fqdn)\b', config_block or '',
                      re.MULTILINE)
    return match.group(1) if match else None


def apply_interface(asa, settings):
    """
    Set the interface address. Returns 'changed', 'unchanged' or 'failed'.
    """
    target = (settings['ip_address'], settings['netmask'])
    before = show_interface(asa, settings['interface'])

    if not before or 'Invalid input' in before:
        error(f"Could not read {settings['interface']} from the running config. "
              f"Check the interface name.")
        return 'failed'

    if 'nameif' not in before:
        error(f"{settings['interface']} has no nameif configured — the ASA will "
              f"reject 'ip address' until one is set. Run the full "
              f"asa-config-vpn.py first.")
        return 'failed'

    existing = current_ip(before)
    if existing == target:
        info(f"{settings['interface']} already has {target[0]} {target[1]} — skipping.")
        return 'unchanged'

    if existing:
        info(f"{settings['interface']} currently {existing[0]} {existing[1]}")
    else:
        info(f"{settings['interface']} currently has no IP address configured.")

    output = asa.send_config_commands(
        build_interface_commands(settings),
        description=f"Set {settings['interface']} to {settings['ip_address']}"
    )
    if output is None:
        error("Failed to send interface commands")
        return 'failed'

    applied = current_ip(show_interface(asa, settings['interface']))
    if applied == target:
        success(f"{settings['interface']} now {applied[0]} {applied[1]}")
        return 'changed'

    error(f"Interface verification failed — device reports "
          f"{' '.join(applied) if applied else 'no address'}")
    return 'failed'


def apply_object(asa, settings):
    """
    Point the network object at the subnet the new address sits in.
    Returns 'changed', 'unchanged' or 'failed'.
    """
    name = settings['object_name']
    target = (settings['subnet'], settings['subnet_mask'])
    before = show_object(asa, name)

    body = object_body_type(before)
    if body and body != 'subnet':
        error(f"object network {name} currently holds a '{body}' entry, not a "
              f"subnet. Refusing to overwrite it — check ASA_DT_OBJECT.")
        return 'failed'

    existing = current_subnet(before)
    if existing == target:
        info(f"object network {name} already has {target[0]} {target[1]} — skipping.")
        return 'unchanged'

    if existing:
        info(f"object network {name} currently {existing[0]} {existing[1]}")
    else:
        # No output at all means the object does not exist yet; the commands
        # below create it, which is the right outcome either way.
        info(f"object network {name} not found — it will be created.")

    output = asa.send_config_commands(
        build_object_commands(settings),
        description=f"Set object network {name} to {target[0]} {target[1]}"
    )
    if output is None:
        error("Failed to send object commands")
        return 'failed'

    applied = current_subnet(show_object(asa, name))
    if applied == target:
        success(f"object network {name} now {applied[0]} {applied[1]}")
        return 'changed'

    error(f"Object verification failed — device reports "
          f"{' '.join(applied) if applied else 'no subnet'}")
    return 'failed'


def main():
    parser = argparse.ArgumentParser(
        description="Change the IP address on the ASA DT interface (Ethernet1/9) "
                    "and keep the matching network object subnet in step."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the commands without connecting to the device")
    parser.add_argument("--no-save", action="store_true",
                        help="Apply the change but do not write to startup-config")
    parser.add_argument("--verbose", action="store_true",
                        help="Echo raw console output")

    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--skip-object", action="store_true",
                       help="Change the interface only, leave the network object alone")
    scope.add_argument("--object-only", action="store_true",
                       help="Change the network object only, leave the interface alone")

    args = parser.parse_args()

    settings = read_env()
    do_interface = not args.object_only
    do_object = not args.skip_object

    print(f"\n{Colors.BOLD}DT address change{Colors.RESET}")
    if do_interface:
        print(f"  Interface : {settings['interface']} "
              f"(expected nameif {settings['nameif']})")
        print(f"  New IP    : {settings['ip_address']} {settings['netmask']}  "
              f"[{settings['network']}]")
    if do_object:
        print(f"  Object    : {settings['object_name']}")
        print(f"  Subnet    : {settings['subnet']} {settings['subnet_mask']}")

    if args.dry_run:
        print(f"\n{Colors.CYAN}{Colors.BOLD}--- DRY RUN MODE ---{Colors.RESET}")
        print("Commands to be sent:")
        print("-" * 40)
        if do_interface:
            print("  configure terminal")
            for cmd in build_interface_commands(settings):
                print(f"  {cmd}")
            print("  exit")
        if do_object:
            print("  configure terminal")
            for cmd in build_object_commands(settings):
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

        # connect() reports success even when enable-mode entry failed, so
        # confirm the '#' prompt ourselves before touching the config.
        auth_secret = (os.getenv('ASA_SECRET')
                       or os.getenv('ASA_KNOWN_SECRET', 'Cisco123'))
        if not ensure_enable(asa, auth_secret):
            return 1

        timeout_mins = console_timeout_value(asa)
        if timeout_mins is not None and timeout_mins != 0:
            info(f"Device has 'console timeout {timeout_mins}' — the session will "
                 f"log out after {timeout_mins} min idle. Each stage re-checks "
                 f"the prompt.")

        outcomes = []

        if do_interface:
            if not ensure_enable(asa, auth_secret):
                return 1
            result = apply_interface(asa, settings)
            if result == 'failed':
                return 1
            outcomes.append(result)

        if do_object:
            # Run even when the interface was already correct — the object can
            # be out of step on its own, e.g. after a partial earlier run.
            if not ensure_enable(asa, auth_secret):
                return 1
            result = apply_object(asa, settings)
            if result == 'failed':
                if 'changed' in outcomes:
                    warn("The interface address WAS changed but the object was not. "
                         "The running config is now inconsistent — fix the object "
                         "before saving.")
                return 1
            outcomes.append(result)

        if 'changed' not in outcomes:
            success("Everything already matches the requested address — nothing to do.")
            return 0

        if args.no_save:
            warn("Changes are in the running config only. They will be lost on "
                 "reload (re-run without --no-save, or issue 'write memory').")
        else:
            if not ensure_enable(asa, auth_secret):
                error("Lost the enable prompt before saving — changes are in the "
                      "running config only.")
                return 1
            if asa.save_config():
                success("Saved to startup-config")
            else:
                warn("Changes applied but the startup-config save failed — "
                     "they will not survive a reload.")
                return 1

        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ COMPLETE{Colors.RESET}")
        return 0

    except KeyboardInterrupt:
        warn("Cancelled by user — the config may be partially applied.")
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
