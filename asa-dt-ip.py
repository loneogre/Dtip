#!/usr/bin/env python3
"""
asa_set_dt_ip.py — DT interface address, network object, and the SIEM / AGENT /
PAT NAT + ACL entries on a Cisco ASA over the serial console.

Everything is a command-line argument except the enable password, which stays
in the environment: ASA_SECRET (or ASA_KNOWN_SECRET, default Cisco123).

  --ip ADDR              Required. New IP address for the DT interface.
  --netmask MASK         Default 255.255.255.0
  --interface NAME       Default Ethernet1/9
  --nameif NAME          Default DTOUT
  --object NAME          Default DTIP — holds the DT subnet
  --sensor-nameif NAME   Default SENSORPORT
  --acl NAME             Default DTOUT_IN

  --siem  enable|disable   SIEM-VM  NAT + ACL entry
  --agent enable|disable   AGENT-VM NAT + ACL entry
  --pat   enable|disable   Global after-auto PAT rule
  --lindef enable|disable  LINDEF-VM in the egress group (no NAT, no ACL)
  --windef enable|disable  WINDEF1-4 in the egress group (no NAT, no ACL)
  --siem-host / --agent-host   Host IP, only needed when creating the object

--agent also adds or removes AGENT-VM in the egress object-group. --siem does
not. --lindef and --windef only touch group membership — the objects ride the
PAT rule out and have no NAT or ACL entry of their own.

Omitting a feature flag leaves that feature exactly as it is on the device.

Admin state: once features have been applied, the interface is shut when none
of the three are enabled and brought up when at least one is. The decision is
made from the device's running config, not just the flags given, so features
you did not name are still counted. Suppress with --no-auto-shutdown. A run
with no feature flags at all never touches the admin state.

Usage:
  export ASA_SECRET=...
  ./asa_set_dt_ip.py --ip 192.168.20.45 --siem enable --agent enable --pat enable
  ./asa_set_dt_ip.py --ip 192.168.20.45 --siem disable --agent disable --pat disable
  ./asa_set_dt_ip.py --ip 192.168.20.45 --dry-run
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
DEFAULT_ACL = 'DTOUT_IN'
DEFAULT_PAT_GROUP = 'OVN-EGRESS'

# Objects that are only ever members of the egress object-group — no NAT and no
# ACL entry of their own, they just ride the PAT rule out.
EGRESS_MEMBERS = [
    {'key': 'lindef', 'flag': '--lindef', 'objects': ['LINDEF-VM']},
    {'key': 'windef', 'flag': '--windef',
     'objects': ['WINDEF1', 'WINDEF2', 'WINDEF3', 'WINDEF4']},
]

# The three optional NAT features, driven by ASA_SIEM / ASA_AGENT / ASA_PAT.
# 1 = configure, 0 = delete, unset = leave exactly as it is.
NAT_OBJECTS = [
    {
        'key': 'siem',
        'flag': '--siem',
        'host_key': 'siem_host',
        'host_flag': '--siem-host',
        'object': 'SIEM-VM',
        'protocol': 'tcp',
        'real_port': '9999',
        'mapped_port': '9997',
    },
    {
        'key': 'agent',
        'flag': '--agent',
        'host_key': 'agent_host',
        'host_flag': '--agent-host',
        'object': 'AGENT-VM',
        'egress': True,
        'protocol': 'tcp',
        'real_port': '8000',
        'mapped_port': '8000',
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



def parse_args(argv=None):
    """Everything except the enable password comes from the command line."""
    parser = argparse.ArgumentParser(
        description="Change the IP address on the ASA DT interface, keep the "
                    "matching network object in step, and enable or disable the "
                    "SIEM / AGENT / PAT NAT and ACL entries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--ip", required=True, metavar="ADDR",
                        help="New IP address for the DT interface")
    parser.add_argument("--netmask", default=DEFAULT_NETMASK, metavar="MASK",
                        help="Dotted-decimal netmask")
    parser.add_argument("--interface", default=DEFAULT_INTERFACE,
                        help="Hardware interface to change")
    parser.add_argument("--nameif", default=DEFAULT_NAMEIF,
                        help="Expected nameif on that interface")
    parser.add_argument("--object", dest="object_name", default=DEFAULT_OBJECT,
                        help="Network object holding the DT subnet")
    parser.add_argument("--sensor-nameif", default=DEFAULT_SENSOR_NAMEIF,
                        help="Source nameif for the NAT rules")
    parser.add_argument("--acl", default=DEFAULT_ACL,
                        help="Inbound ACL that carries the SIEM/AGENT entries")

    toggle = ('enable', 'disable')
    features = parser.add_argument_group(
        'features',
        'Omit a feature to leave it exactly as it is on the device.')
    features.add_argument("--siem", choices=toggle,
                          help="SIEM-VM NAT + ACL entry")
    features.add_argument("--agent", choices=toggle,
                          help="AGENT-VM NAT + ACL entry")
    features.add_argument("--pat", choices=toggle,
                          help="Global after-auto PAT rule")
    features.add_argument("--lindef", choices=toggle,
                          help="LINDEF-VM membership of the egress group "
                               "(no NAT, no ACL)")
    features.add_argument("--windef", choices=toggle,
                          help="WINDEF1-4 membership of the egress group "
                               "(no NAT, no ACL)")
    features.add_argument("--siem-host", metavar="ADDR",
                          help="Host IP, only needed when creating SIEM-VM")
    features.add_argument("--agent-host", metavar="ADDR",
                          help="Host IP, only needed when creating AGENT-VM")
    features.add_argument("--pat-group", default=DEFAULT_PAT_GROUP,
                          help="Source object-group for the PAT rule")
    features.add_argument("--pat-description", metavar="TEXT",
                          help="Override the PAT rule description")

    parser.add_argument("--no-auto-shutdown", action="store_true",
                        help="Do not shut/no-shut the interface based on whether "
                             "any feature is left enabled")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the commands without connecting to the device")
    parser.add_argument("--no-save", action="store_true",
                        help="Apply changes but do not write to startup-config")
    parser.add_argument("--verbose", action="store_true",
                        help="Echo raw console output")

    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--skip-object", action="store_true",
                       help="Change the interface only, leave the network object alone")
    scope.add_argument("--object-only", action="store_true",
                       help="Change the network object only, leave the interface alone")

    return parser.parse_args(argv)


def build_settings(args):
    """Validate the arguments and derive everything that follows from them."""
    try:
        addr = ipaddress.IPv4Address(args.ip)
    except ipaddress.AddressValueError:
        error(f"--ip is not a valid IPv4 address: {args.ip}")
        sys.exit(1)

    try:
        network = ipaddress.IPv4Network(f"{args.ip}/{args.netmask}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        error(f"--netmask is not a valid dotted-decimal mask: {args.netmask}")
        sys.exit(1)

    # An ASA will accept these and then quietly black-hole the interface.
    if network.prefixlen < 31:
        if addr == network.network_address:
            error(f"{args.ip} is the network address of {network} — "
                  f"pick a host address.")
            sys.exit(1)
        if addr == network.broadcast_address:
            error(f"{args.ip} is the broadcast address of {network} — "
                  f"pick a host address.")
            sys.exit(1)

    if not re.match(r'^[A-Za-z]+\d+/\d+$', args.interface):
        error(f"--interface does not look like a hardware interface: {args.interface}")
        sys.exit(1)

    if not re.match(r'^[A-Za-z0-9_.\-]{1,64}$', args.object_name):
        error(f"--object is not a valid object name: {args.object_name}")
        sys.exit(1)

    for label, host in (('--siem-host', args.siem_host),
                        ('--agent-host', args.agent_host)):
        if host:
            try:
                ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError:
                error(f"{label} is not a valid IPv4 address: {host}")
                sys.exit(1)

    def want(value):
        """'enable' -> True, 'disable' -> False, omitted -> None (leave alone)."""
        return None if value is None else (value == 'enable')

    return {
        'ip_address': args.ip,
        'netmask': args.netmask,
        'interface': args.interface,
        'nameif': args.nameif,
        'network': str(network),
        'object_name': args.object_name,
        # The object holds the SUBNET the DT address sits in, not the host
        # address, so it is derived from the network the new IP falls in.
        'subnet': str(network.network_address),
        'subnet_mask': str(network.netmask),
        'sensor_nameif': args.sensor_nameif,
        'acl_name': args.acl,
        'pat_group': args.pat_group,
        'pat_description': (args.pat_description
                            or f"PAT all over egress behind {args.ip}"),
        'siem': want(args.siem),
        'lindef': want(args.lindef),
        'windef': want(args.windef),
        'agent': want(args.agent),
        'pat': want(args.pat),
        'siem_host': args.siem_host,
        'agent_host': args.agent_host,
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


def object_block(config_text, object_name, keyword='object network'):
    """
    Slice one object's block out of a running-config dump, including anything
    indented under it — the 'host' line AND the nested 'nat (...)' line.

    Object NAT lives inside the object block, not in the global NAT section, so
    this is what has to be parsed to see a SIEM-VM / AGENT-VM NAT rule. Pass
    keyword='object-group network' to slice a group's member list instead.
    """
    header = re.compile(rf'^{re.escape(keyword)} {re.escape(object_name)}\s*$')
    captured = []
    capturing = False

    for line in (config_text or '').splitlines():
        if not capturing:
            if header.match(line.strip()) and not line[:1].isspace():
                capturing = True
                captured.append(line.strip())
            continue
        # Indented lines belong to this object; the first unindented line ends it.
        if line[:1].isspace():
            captured.append(line.rstrip())
        elif line.strip() == '':
            continue
        else:
            break

    return '\n'.join(captured)


def show_object(asa, object_name):
    """
    Return the running-config block for one network object.

    'show running-config object id NAME' is not accepted on every ASA build and
    returns nothing useful on some, so pull the whole object-network section and
    slice the block out of it. Falls back to the per-object form if the section
    dump comes back empty.
    """
    output = asa.send_command('show running-config object network', timeout=20)
    block = object_block(output, object_name)
    if block:
        return block

    output = asa.send_command(f'show running-config object id {object_name}',
                              timeout=10)
    block = object_block(output, object_name)
    if block:
        return block

    # Nothing found. Hand back the raw reply so callers can report what the
    # device actually said rather than guessing.
    return ''


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


def build_nat_object_commands(settings, spec, enable, existing=None):
    """
    Config commands to add or remove one object NAT rule.

    On removal, `existing` is the rule as the device actually has it. Removing
    by the device's own wording matters when the rule on the box differs from
    the one we would build (different ports, say) — the ASA matches the whole
    line, so a near-miss removes nothing.
    """
    if enable:
        commands = [f"object network {spec['object']}"]
        host = settings.get(spec['host_key'])
        if host:
            commands.append(f" host {host}")
        commands.append(f" {nat_line(settings, spec)}")
        return commands
    # Remove the NAT only. The object itself is left in place because ACLs and
    # other rules may still reference it; deleting it would break them.
    # 'no nat' on its own is an incomplete command — the whole rule has to be
    # repeated after the 'no'.
    return [f"object network {spec['object']}",
            f" no {existing or nat_line(settings, spec)}"]


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
    """Return the NAT section of the running config."""
    return asa.send_command('show running-config nat', timeout=20)


def object_nat_rule(asa, object_name, nat_config=None):
    """
    Return the object (auto) NAT line for one object, or None.

    On this platform object NAT does NOT appear under
    'show running-config object network' — it is printed by
    'show running-config nat', beneath its own 'object network NAME' header:

        object network SIEM-VM
         nat (SENSORPORT,DTOUT) static interface service tcp 9999 9997

    The object-network section is still checked as a fallback, since some
    builds do print it there.
    """
    text = nat_config if nat_config is not None else show_nat(asa)
    rule = object_nat_line(object_block(text, object_name))
    if rule:
        return rule
    return object_nat_line(show_object(asa, object_name))


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
    existing = object_nat_rule(asa, name)
    wanted = nat_line(settings, spec)

    if enable:
        if existing == wanted:
            info(f"{name}: NAT already correct — skipping.")
            return 'unchanged'

        # Object NAT needs an address on the object; the ASA rejects the nat
        # line otherwise. Only the host env var can supply one we don't have.
        before = show_object(asa, name)
        if not before:
            error(f"object network {name} was not found in the running config. "
                  f"Create it first, or pass {spec['host_flag']} with its host "
                  f"IP and this script will create it.")
            return 'failed'

        if not object_body_type(before) and not settings.get(spec['host_key']):
            error(f"object network {name} exists but has no host/subnet. The ASA "
                  f"rejects a NAT line on an object with no address — pass "
                  f"{spec['host_flag']} with its host IP.")
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
        build_nat_object_commands(settings, spec, enable, existing),
        description=f"{'Configure' if enable else 'Delete'} NAT on {name}"
    )
    if output is None:
        error(f"Failed to send NAT commands for {name}")
        return 'failed'

    applied = object_nat_rule(asa, name)
    if enable and applied == wanted:
        success(f"{name}: {wanted}")
        return 'changed'
    if not enable and not applied:
        success(f"{name}: NAT rule removed")
        return 'changed'

    error(f"{name}: verification failed — device reports {applied!r}")
    return 'failed'


def acl_line(settings, spec):
    """
    The ACE that lets traffic reach the object, e.g.
    'access-list DTOUT_IN extended permit tcp any object SIEM-VM eq 9999 log'.

    The port is the REAL port, not the mapped one — post-8.3 ASA matches ACLs
    against the untranslated address and port.
    """
    return (f"access-list {settings['acl_name']} extended permit "
            f"{spec['protocol']} any object {spec['object']} "
            f"eq {spec['real_port']} log")


def show_acl(asa, acl_name):
    """Return the running config for one access-list."""
    return asa.send_command(f'show running-config access-list {acl_name}', timeout=20)


def normalise_ace(line):
    """Drop any 'line N' sequence number the device prints back."""
    return re.sub(r'^(access-list \S+) line \d+ ', r'\1 ', line.strip())


def find_acl_entry(acl_config, settings, spec):
    """
    Return the existing ACE referencing this object, as the device words it,
    or None. Matching on the object name rather than the whole line means a
    stale entry with the wrong port is still found — and can then be removed
    using the device's own wording.
    """
    pattern = (rf'^\s*(access-list {re.escape(settings["acl_name"])}\b.*'
               rf'\bobject {re.escape(spec["object"])}\b.*)$')
    match = re.search(pattern, acl_config or '', re.MULTILINE)
    return normalise_ace(match.group(1)) if match else None


def build_acl_commands(settings, spec, enable, existing=None):
    """Config commands to add or remove the ACE for one object."""
    if enable:
        return [acl_line(settings, spec)]
    return [f"no {existing or acl_line(settings, spec)}"]


def apply_acl(asa, settings, spec, enable):
    """
    Add or remove the ACE for one object. Returns 'changed', 'unchanged'
    or 'failed'.
    """
    acl = settings['acl_name']
    name = spec['object']
    config = show_acl(asa, acl)
    existing = find_acl_entry(config, settings, spec)
    wanted = acl_line(settings, spec)

    if enable:
        if existing == wanted:
            info(f"{acl}: ACE for {name} already correct — skipping.")
            return 'unchanged'
        if existing:
            # Wrong port or options — remove the old one first, or the ASA
            # keeps both and the stale entry may match first.
            info(f"{acl}: replacing {existing}")
            asa.send_config_commands(build_acl_commands(settings, spec, False, existing),
                                     description=f"Remove stale ACE for {name}")
        else:
            info(f"{acl}: adding ACE for {name}")
            if not config:
                warn(f"{acl} does not exist yet — this ACE will create it. Make "
                     f"sure it is applied to the interface with "
                     f"'access-group {acl} in interface {settings['nameif']}'.")
    else:
        if not existing:
            info(f"{acl}: no ACE for {name} — nothing to delete.")
            return 'unchanged'
        info(f"{acl}: removing {existing}")

    output = asa.send_config_commands(
        build_acl_commands(settings, spec, enable, existing),
        description=f"{'Configure' if enable else 'Delete'} ACE for {name}"
    )
    if output is None:
        error(f"Failed to send ACL commands for {name}")
        return 'failed'

    applied = find_acl_entry(show_acl(asa, acl), settings, spec)
    if enable and applied == wanted:
        success(f"{acl}: {wanted}")
        return 'changed'
    if not enable and not applied:
        success(f"{acl}: ACE for {name} removed")
        return 'changed'

    error(f"{acl}: verification failed — device reports {applied!r}")
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



def show_object_group(asa, group_name):
    """Return the running-config block for one object-group."""
    output = asa.send_command('show running-config object-group', timeout=20)
    block = object_block(output, group_name, keyword='object-group network')
    if block:
        return block
    output = asa.send_command(f'show running-config object-group id {group_name}',
                              timeout=10)
    return object_block(output, group_name, keyword='object-group network')


def group_members(group_block):
    """The object names listed as 'network-object object NAME' in a group."""
    return set(re.findall(r'^\s*network-object object (\S+)\s*$',
                          group_block or '', re.MULTILINE))


def build_group_commands(settings, names, enable):
    """Config commands to add or remove members of the egress object-group."""
    commands = [f"object-group network {settings['pat_group']}"]
    prefix = '' if enable else 'no '
    commands += [f" {prefix}network-object object {name}" for name in names]
    return commands


def apply_egress_members(asa, settings, label, names, enable):
    """
    Add or remove object-group members. Returns 'changed', 'unchanged'
    or 'failed'.
    """
    group = settings['pat_group']
    block = show_object_group(asa, group)

    if not block:
        error(f"object-group network {group} was not found. Create it first — "
              f"this script will not create the group itself.")
        return 'failed'

    present = group_members(block)
    if enable:
        todo = [n for n in names if n not in present]
        if not todo:
            info(f"{group}: {label} already a member — skipping.")
            return 'unchanged'

        # The ASA rejects 'network-object object X' when X does not exist.
        defined = show_object_network_names(asa)
        missing = [n for n in todo if n not in defined]
        if missing:
            error(f"These objects do not exist, so they cannot be added to "
                  f"{group}: {', '.join(missing)}. Create them first.")
            return 'failed'

        info(f"{group}: adding {', '.join(todo)}")
    else:
        todo = [n for n in names if n in present]
        if not todo:
            info(f"{group}: {label} not a member — nothing to delete.")
            return 'unchanged'

        # The ASA will not let the last member leave a group that an active NAT
        # rule still points at — the rule would be left referencing nothing.
        # The PAT rule has to go first, which is why a disable run removes it
        # before touching membership.
        if not (present - set(todo)):
            blocking = find_pat_rule(show_nat(asa), settings)
            if blocking:
                error(f"Removing {', '.join(todo)} would leave {group} empty, and "
                      f"the PAT rule still references it — the ASA rejects that. "
                      f"Pass --pat disable in the same run, or leave one member "
                      f"in place.")
                return 'failed'
            warn(f"{group} will be left with no members.")

        info(f"{group}: removing {', '.join(todo)}")

    output = asa.send_config_commands(
        build_group_commands(settings, todo, enable),
        description=f"{'Add' if enable else 'Remove'} {label} in {group}"
    )
    if output is None:
        error(f"Failed to send object-group commands for {label}")
        return 'failed'

    after = group_members(show_object_group(asa, group))
    if enable and all(n in after for n in names):
        success(f"{group}: {', '.join(names)} present")
        return 'changed'
    if not enable and not any(n in after for n in names):
        success(f"{group}: {', '.join(names)} removed")
        return 'changed'

    error(f"{group}: verification failed — members now {sorted(after)}")
    return 'failed'


def show_object_network_names(asa):
    """Every object network name defined on the device."""
    output = asa.send_command('show running-config object network', timeout=20)
    return set(re.findall(r'^object network (\S+)\s*$', output or '', re.MULTILINE))



def feature_state_on_device(asa, settings):
    """
    Read back which of the three features are actually present on the device.

    This is deliberately read from the running config rather than inferred from
    the flags: a run that only passes --siem still needs to know whether AGENT
    and PAT are live before deciding to shut the interface.
    """
    nat_config = show_nat(asa)
    state = {}
    for spec in NAT_OBJECTS:
        state[spec['key']] = object_nat_rule(asa, spec['object'], nat_config) is not None
    state['pat'] = find_pat_rule(nat_config, settings) is not None
    return state


def interface_is_shutdown(config_block):
    """True if the interface block carries a 'shutdown' line."""
    return bool(re.search(r'^\s*shutdown\s*$', config_block or '', re.MULTILINE))


def apply_interface_state(asa, settings):
    """
    Shut the DT interface when no feature is left enabled, bring it up when at
    least one is. Returns 'changed', 'unchanged' or 'failed'.

    With nothing translated or permitted through it, an up interface is just
    exposed surface — so the default posture is down.
    """
    interface = settings['interface']
    state = feature_state_on_device(asa, settings)
    live = [name for name, present in state.items() if present]

    before = show_interface(asa, interface)
    if not before:
        error(f"Could not read {interface} to set its admin state.")
        return 'failed'

    currently_down = interface_is_shutdown(before)
    should_be_down = not live

    if should_be_down == currently_down:
        posture = 'shut' if currently_down else 'up'
        info(f"{interface} is already {posture} "
             f"({'no features enabled' if should_be_down else ', '.join(sorted(live))}).")
        return 'unchanged'

    if should_be_down:
        warn(f"No features left enabled — shutting {interface}. Anything "
             f"reaching the DT network through it will stop.")
        commands = [f"interface {interface}", " shutdown"]
    else:
        info(f"Features enabled ({', '.join(sorted(live))}) — bringing "
             f"{interface} up.")
        commands = [f"interface {interface}", " no shutdown"]

    output = asa.send_config_commands(
        commands, description=f"{'Shut' if should_be_down else 'Enable'} {interface}")
    if output is None:
        error(f"Failed to set admin state on {interface}")
        return 'failed'

    now_down = interface_is_shutdown(show_interface(asa, interface))
    if now_down == should_be_down:
        success(f"{interface} is now {'shut down' if now_down else 'up'}.")
        return 'changed'

    error(f"{interface} admin state verification failed.")
    return 'failed'



def main():
    args = parse_args()
    settings = build_settings(args)

    do_interface = not args.object_only
    do_object = not args.skip_object
    # A feature runs only when its flag was given; omitted means leave it alone.
    nat_specs = [(spec, settings[spec['key']]) for spec in NAT_OBJECTS
                 if settings[spec['key']] is not None]
    egress_specs = [(spec, settings[spec['key']]) for spec in EGRESS_MEMBERS
                    if settings[spec['key']] is not None]
    do_pat = settings['pat'] is not None
    # Only touch the admin state when the run actually decided something about
    # the features — a bare address change should not shut the port.
    do_admin_state = (bool(nat_specs) or do_pat) and not args.no_auto_shutdown

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
        print(f"  {spec['flag']:<8}  : {'enable' if want else 'DISABLE'} "
              f"{spec['object']} (NAT + {settings['acl_name']} ACE)")
    for spec, want in egress_specs:
        print(f"  {spec['flag']:<8}  : {'enable' if want else 'DISABLE'} "
              f"{', '.join(spec['objects'])} in {settings['pat_group']}")
    if do_pat:
        print(f"  --pat     : {'enable' if settings['pat'] else 'DISABLE'} "
              f"{settings['pat_group']} PAT")
    if do_admin_state:
        print(f"  Admin     : {settings['interface']} will be shut if no feature "
              f"is left enabled")

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
        pat_first = do_pat and not settings['pat']
        if pat_first:
            print("  configure terminal")
            for cmd in build_pat_commands(settings, settings['pat']):
                print(f"  {cmd}")
            print("  exit")
        for spec, want in nat_specs:
            print("  configure terminal")
            for cmd in build_nat_object_commands(settings, spec, want):
                print(f"  {cmd}")
            for cmd in build_acl_commands(settings, spec, want):
                print(f"  {cmd}")
            if spec.get('egress'):
                for cmd in build_group_commands(settings, [spec['object']], want):
                    print(f"  {cmd}")
            print("  exit")
        for spec, want in egress_specs:
            print("  configure terminal")
            for cmd in build_group_commands(settings, spec['objects'], want):
                print(f"  {cmd}")
            print("  exit")
        if do_pat and not pat_first:
            print("  configure terminal")
            for cmd in build_pat_commands(settings, settings['pat']):
                print(f"  {cmd}")
            print("  exit")
        if do_admin_state:
            enabled = [s['object'] for s in NAT_OBJECTS if settings[s['key']]]
            if settings['pat']:
                enabled.append('PAT')
            print("  configure terminal")
            print(f"  interface {settings['interface']}")
            print(f"   {'no shutdown' if enabled else 'shutdown'}")
            print("  exit")
            if not enabled:
                print(f"  {Colors.YELLOW}(flags given all disable; on the device "
                      f"the decision also accounts for features not named "
                      f"here){Colors.RESET}")
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

        def run_pat_stage():
            """Returns None to continue, or an exit code to abort with."""
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_pat(asa, settings, settings['pat'])
            if result == 'failed':
                if 'changed' in outcomes:
                    warn("Earlier changes are in the running config but the PAT "
                         "stage failed — review before saving.")
                return 1
            outcomes.append(result)
            return None

        # A PAT rule pointing at the egress group blocks that group from being
        # emptied, so on a disable run it has to come off first. On an enable
        # run the members must exist before the rule that references them, so
        # it goes last.
        pat_first = do_pat and not settings['pat']
        if pat_first:
            failure = run_pat_stage()
            if failure is not None:
                return failure

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

            result = apply_acl(asa, settings, spec, want)
            if result == 'failed':
                warn(f"The NAT for {spec['object']} is in place but its "
                     f"{settings['acl_name']} entry is not — traffic will be "
                     f"translated and then dropped. Fix before saving.")
                return 1
            outcomes.append(result)

            if spec.get('egress'):
                result = apply_egress_members(asa, settings, spec['object'],
                                              [spec['object']], want)
                if result == 'failed':
                    return 1
                outcomes.append(result)

        for spec, want in egress_specs:
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_egress_members(asa, settings, spec['flag'].lstrip('-'),
                                          spec['objects'], want)
            if result == 'failed':
                if 'changed' in outcomes:
                    warn("Earlier changes are in the running config but this "
                         "stage failed — review before saving.")
                return 1
            outcomes.append(result)

        if do_pat and not pat_first:
            failure = run_pat_stage()
            if failure is not None:
                return failure

        if do_admin_state:
            if not enter_enable(asa, auth_secret):
                return 1
            result = apply_interface_state(asa, settings)
            if result == 'failed':
                warn("Feature changes are in the running config but the "
                     f"{settings['interface']} admin state was not set.")
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
