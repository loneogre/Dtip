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

  ASA_SIEM          (optional)  1 = configure SIEM-VM NAT, 0 = delete it
  ASA_AGENT         (optional)  1 = configure AGENT-VM NAT, 0 = delete it
  ASA_PAT           (optional)  1 = configure OVN-EGRESS PAT, 0 = delete it
                                Unset = leave that feature untouched.
  ASA_SIEM_HOST     (optional)  Host IP, only needed when creating SIEM-VM
  ASA_AGENT_HOST    (optional)  Host IP, only needed when creating AGENT-VM
  ASA_SENSOR_NAMEIF (optional)  Source nameif,         default SENSORPORT
  ASA_PAT_GROUP     (optional)  PAT source group,      default OVN-EGRESS
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
DEFAULT_SENSOR_NAMEIF = 'SENSORPORT'
DEFAULT_PAT_GROUP = 'OVN-EGRESS'

# The three optional NAT features, driven by ASA_SIEM / ASA_AGENT / ASA_PAT.
# 1 = configure, 0 = delete, unset = leave exactly as it is.
NAT_OBJECTS = [
    {
        'env': 'ASA_SIEM',
        'object': 'SIEM-VM',
        'protocol': 'tcp',
        'real_port': '9999',
        'mapped_port': '9997',
        'host_env': 'ASA_SIEM_HOST',
    },
    {
        'env': 'ASA_AGENT',
        'object': 'AGENT-VM',
        'protocol': 'tcp',
        'real_port': '8000',
        'mapped_port': '8000',
        'host_env': 'ASA_AGENT_HOST',
    },
]


def info(msg):
    print(f"{Colors.CYAN}[ INFO ]{Colors.RESET} {msg}")


def enter_enable(asa, secret):
    """
    Get the console to a '#' prompt.

    This exists because 'console timeout' logs the session out mid-run and
    drops it back to a user prompt like 'wkgfw>' or 'senfw>'. It does one
    thing: at a '>' prompt, send 'enable', wait for the password prompt, send
    the secret. Safe to call as often as you like.

    Deliberately self-contained — it talks to asa.serial_port directly and
    calls nothing in asa-config-vpn.py, so that file needs no changes.
    """
    port = asa.serial_port

    def send(text):
        port.write((text + '\r').encode('utf-8'))
        port.flush()

    def read(seconds=3.0):
        buf = ''
        deadline = time.time() + seconds
        while time.time() < deadline:
            if port.in_waiting:
                buf += port.read(port.in_waiting).decode('utf-8', errors='ignore')
                deadline = time.time() + 0.4      # keep reading while data flows
            else:
                time.sleep(0.05)
        if asa.verbose and buf:
            print(buf, end='', flush=True)
        return buf

    # Bin anything stale, then ask for a fresh prompt.
    try:
        if port.in_waiting:
            port.read(port.in_waiting)
    except Exception as e:
        logging.debug(f"Buffer drain failed: {e}")

    send('')
    output = read()

    if '#' in output:
        return True

    if 'assword' in output.lower():          # already sitting at the prompt
        send(secret)
        return '#' in read()

    if '>' not in output:
        error(f"No prompt from the console. Got: {output.strip()[-120:]!r}")
        return False

    info("Session is at a user prompt — entering enable mode.")
    send('enable')
    output = read()

    if '#' in output:
        return True                          # no enable password set

    if 'assword' in output.lower():
        send(secret)
        output = read()
        if '#' in output:
            success("Enable mode entered.")
            return True

    # A console logout also resets 'terminal pager 0', which makes later
    # 'show running-config' calls stall on <--- More --->.
    error("Could not reach enable mode. Check ASA_SECRET / ASA_KNOWN_SECRET. "
          f"Last output: {output.strip()[-120:]!r}")
    return False


def restore_pager(asa):
    """Re-apply pager/width, which a console-timeout logout resets."""
    for cmd in ('terminal pager 0', 'terminal width 200'):
        asa.send_command(cmd, timeout=5)



def parse_toggle(name):
    """
    Read a 1/0 style switch. Returns True, False, or None when the variable is
    not set at all — unset means 'leave this feature alone', which is different
    from 0 ('delete it').
    """
    raw = os.getenv(name)
    if raw is None or raw.strip() == '':
        return None
    value = raw.strip().lower()
    if value in ('1', 'true', 'yes', 'on', 'enable', 'enabled'):
        return True
    if value in ('0', 'false', 'no', 'off', 'disable', 'disabled'):
        return False
    error(f"{name} must be 1 or 0 (got {raw!r})")
    sys.exit(1)


def read_env():
    """Collect and validate the inputs from the environment."""
    ip_address = os.getenv('ASA_DT_IP')
    netmask = os.getenv('ASA_DT_NETMASK', DEFAULT_NETMASK)
    interface = os.getenv('ASA_DT_INTERFACE', DEFAULT_INTERFACE)
    nameif = os.getenv('ASA_DT_NAMEIF', DEFAULT_NAMEIF)
    object_name = os.getenv('ASA_DT_OBJECT', DEFAULT_OBJECT)
    sensor_nameif = os.getenv('ASA_SENSOR_NAMEIF', DEFAULT_SENSOR_NAMEIF)
    pat_group = os.getenv('ASA_PAT_GROUP', DEFAULT_PAT_GROUP)

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
        'sensor_nameif': sensor_nameif,
        'pat_group': pat_group,
        'pat_description': os.getenv(
            'ASA_PAT_DESCRIPTION',
            f"PAT all over egress behind {ip_address}"),
        'siem': parse_toggle('ASA_SIEM'),
        'agent': parse_toggle('ASA_AGENT'),
        'pat': parse_toggle('ASA_PAT'),
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


def nat_line(settings, spec):
    """The object-NAT line, e.g. 'nat (SENSORPORT,DTOUT) static interface service tcp 9999 9997'."""
    return (f"nat ({settings['sensor_nameif']},{settings['nameif']}) "
            f"static interface service {spec['protocol']} "
            f"{spec['real_port']} {spec['mapped_port']}")


def pat_line(settings, with_description=True):
    """
    The global after-auto PAT rule. The description carries the DT address, so
    it changes whenever ASA_DT_IP changes.
    """
    line = (f"nat ({settings['sensor_nameif']},{settings['nameif']}) after-auto "
            f"source dynamic {settings['pat_group']} interface")
    if with_description:
        line += f" description {settings['pat_description']}"
    return line


def build_nat_object_commands(settings, spec, enable):
    """Config commands to add or remove one object NAT rule."""
    if enable:
        commands = [f"object network {spec['object']}"]
        host = os.getenv(spec['host_env'])
        if host:
            commands.append(f" host {host}")
        commands.append(f" {nat_line(settings, spec)}")
        return commands
    # Remove the NAT only. The object itself is left in place because ACLs and
    # other rules may still reference it; deleting it would break them.
    return [f"object network {spec['object']}", " no nat"]


def build_pat_commands(settings, enable):
    """Config commands to add or remove the global after-auto PAT rule."""
    if enable:
        return [pat_line(settings)]
    # Removal matches on the rule itself; the description is not part of the match.
    return [f"no {pat_line(settings, with_description=False)}"]


def object_nat_line(config_block):
    """Pull the 'nat (...)' line out of a running-config object block."""
    match = re.search(r'^\s*(nat \(.*)$', config_block or '', re.MULTILINE)
    return match.group(1).strip() if match else None


def show_nat(asa):
    """Return the global NAT section of the running config."""
    return asa.send_command('show running-config nat', timeout=15)


def find_pat_rule(nat_config, settings):
    """Return the existing after-auto PAT line for our group, if any."""
    pattern = (rf'^\s*(nat \({re.escape(settings["sensor_nameif"])},'
               rf'{re.escape(settings["nameif"])}\) after-auto source dynamic '
               rf'{re.escape(settings["pat_group"])}\b.*)$')
    match = re.search(pattern, nat_config or '', re.MULTILINE)
    return match.group(1).strip() if match else None


def apply_nat_object(asa, settings, spec, enable):
    """
    Add or remove one object NAT rule. Returns 'changed', 'unchanged' or 'failed'.
    """
    name = spec['object']
    before = show_object(asa, name)
    existing = object_nat_line(before)
    wanted = nat_line(settings, spec)

    if enable:
        if existing == wanted:
            info(f"{name}: NAT already correct — skipping.")
            return 'unchanged'

        # Object NAT needs an address on the object; the ASA rejects the nat
        # line otherwise. Only the host env var can supply one we don't have.
        if not object_body_type(before) and not os.getenv(spec['host_env']):
            error(f"object network {name} does not exist or has no address. "
                  f"Set {spec['host_env']} to its host IP, or create the object "
                  f"first — the ASA will reject the NAT line without one.")
            return 'failed'

        if existing:
            info(f"{name}: replacing {existing}")
        else:
            info(f"{name}: adding NAT rule")
    else:
        if not existing:
            info(f"{name}: no NAT rule present — nothing to delete.")
            return 'unchanged'
        info(f"{name}: removing {existing}")

    output = asa.send_config_commands(
        build_nat_object_commands(settings, spec, enable),
        description=f"{'Configure' if enable else 'Delete'} NAT on {name}"
    )
    if output is None:
        error(f"Failed to send NAT commands for {name}")
        return 'failed'

    applied = object_nat_line(show_object(asa, name))
    if enable and applied == wanted:
        success(f"{name}: {wanted}")
        return 'changed'
    if not enable and not applied:
        success(f"{name}: NAT rule removed")
        return 'changed'

    error(f"{name}: verification failed — device reports {applied!r}")
    return 'failed'


def apply_pat(asa, settings, enable):
    """
    Add or remove the global after-auto PAT rule. Returns 'changed',
    'unchanged' or 'failed'.
    """
    group = settings['pat_group']
    existing = find_pat_rule(show_nat(asa), settings)
    wanted = pat_line(settings)

    if enable:
        if existing == wanted:
            info(f"PAT: rule already correct — skipping.")
            return 'unchanged'
        if existing:
            # An address change rewrites the description, so the old rule has
            # to go first — the ASA will not merge two after-auto rules.
            info(f"PAT: replacing {existing}")
            asa.send_config_commands(build_pat_commands(settings, False),
                                     description="Remove stale PAT rule")
        else:
            info(f"PAT: adding rule for {group}")
    else:
        if not existing:
            info("PAT: no rule present — nothing to delete.")
            return 'unchanged'
        info(f"PAT: removing {existing}")

    output = asa.send_config_commands(
        build_pat_commands(settings, enable),
        description=f"{'Configure' if enable else 'Delete'} PAT for {group}"
    )
    if output is None:
        error("Failed to send PAT commands")
        return 'failed'

    applied = find_pat_rule(show_nat(asa), settings)
    if enable and applied == wanted:
        success(f"PAT: {wanted}")
        return 'changed'
    if not enable and not applied:
        success("PAT: rule removed")
        return 'changed'

    error(f"PAT: verification failed — device reports {applied!r}")
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
    # Each NAT feature runs only when its variable is set. Unset means leave it.
    nat_specs = [(spec, settings[spec['env'].replace('ASA_', '').lower()])
                 for spec in NAT_OBJECTS]
    nat_specs = [(spec, want) for spec, want in nat_specs if want is not None]
    do_pat = settings['pat'] is not None

    print(f"\n{Colors.BOLD}DT address change{Colors.RESET}")
    if do_interface:
        print(f"  Interface : {settings['interface']} "
              f"(expected nameif {settings['nameif']})")
        print(f"  New IP    : {settings['ip_address']} {settings['netmask']}  "
              f"[{settings['network']}]")
    if do_object:
        print(f"  Object    : {settings['object_name']}")
        print(f"  Subnet    : {settings['subnet']} {settings['subnet_mask']}")
    for spec, want in nat_specs:
        print(f"  {spec['env']:<10}: {'configure' if want else 'DELETE'} "
              f"{spec['object']}")
    if do_pat:
        print(f"  ASA_PAT   : {'configure' if settings['pat'] else 'DELETE'} "
              f"{settings['pat_group']} PAT")

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
        for spec, want in nat_specs:
            print("  configure terminal")
            for cmd in build_nat_object_commands(settings, spec, want):
                print(f"  {cmd}")
            print("  exit")
        if do_pat:
            print("  configure terminal")
            for cmd in build_pat_commands(settings, settings['pat']):
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

        # connect() reports success even when its own enable-mode entry
        # failed, so get to '#' ourselves before touching the config.
        auth_secret = (os.getenv('ASA_SECRET')
                       or os.getenv('ASA_KNOWN_SECRET', 'Cisco123'))
        if not enter_enable(asa, auth_secret):
            return 1
        restore_pager(asa)

        outcomes = []

        if do_interface:
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_interface(asa, settings)
            if result == 'failed':
                return 1
            outcomes.append(result)

        if do_object:
            # Run even when the interface was already correct — the object can
            # be out of step on its own, e.g. after a partial earlier run.
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_object(asa, settings)
            if result == 'failed':
                if 'changed' in outcomes:
                    warn("The interface address WAS changed but the object was not. "
                         "The running config is now inconsistent — fix the object "
                         "before saving.")
                return 1
            outcomes.append(result)

        for spec, want in nat_specs:
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_nat_object(asa, settings, spec, want)
            if result == 'failed':
                if 'changed' in outcomes:
                    warn("Earlier changes are in the running config but this "
                         "stage failed — review before saving.")
                return 1
            outcomes.append(result)

        if do_pat:
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_pat(asa, settings, settings['pat'])
            if result == 'failed':
                if 'changed' in outcomes:
                    warn("Earlier changes are in the running config but the PAT "
                         "stage failed — review before saving.")
                return 1
            outcomes.append(result)

        if 'changed' not in outcomes:
            success("Everything already matches the requested state — nothing to do.")
            return 0

        if args.no_save:
            warn("Changes are in the running config only. They will be lost on "
                 "reload (re-run without --no-save, or issue 'write memory').")
        else:
            if not enter_enable(asa, auth_secret):
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
