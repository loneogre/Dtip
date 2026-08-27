#!/usr/bin/env python3
"""
asa_dt_status.py — read-only status of everything asa-dt-reconfigure.py configures.

Connects over the serial console, reads the running config, and reports the
state of the DT interface, the DTIP object, the SIEM / AGENT NAT and ACL
entries, the OVN-EGRESS group membership, and the PAT rule. It sends no
configuration commands and never writes to startup-config.

Beyond reporting each item it cross-checks them, so it will tell you when
things are individually present but inconsistent with each other — a NAT
without its ACL, a DTIP subnet that no longer matches the interface, a PAT
description still naming the old address, or an interface shut down while
features are live.

It imports asa-dt-reconfigure.py from the same directory for the console
handling and the running-config parsers, so the two cannot drift apart.

Credentials come from the environment, as with asa-dt-reconfigure.py:
  ASA_SECRET (or ASA_KNOWN_SECRET, default Cisco123)

Everything else is a flag; the defaults match asa-dt-reconfigure.py.

Usage:
  export ASA_SECRET=...
  ./asa_dt_status.py
  ./asa_dt_status.py --json
  ./asa_dt_status.py --interface Ethernet1/9 --acl DTOUT_IN
"""

import argparse
import importlib.util
import ipaddress
import json
import os
import sys

# The reconfigure script holds the console handling and every running-config
# parser this script needs, so they are reused rather than reimplemented. It
# lives alongside this file.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_sibling(module_name, filenames):
    for filename in filenames:
        path = os.path.join(_SCRIPT_DIR, filename)
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    print(f"[ ERROR ] Could not find {' or '.join(filenames)} in {_SCRIPT_DIR}. "
          f"Keep this script in the same directory as the reconfigure script.")
    sys.exit(1)


# Hyphens are not legal in Python module names, so the reconfigure script
# cannot be imported by name — it is loaded by file path. Earlier spellings are
# kept as fallbacks so a rename in either direction keeps working.
RECONFIGURE_FILENAMES = [
    'asa-dt-reconfigure.py',
    'asa_dt_reconfigure.py',
    'asa_set_dt_ip.py',
]

dt = _load_sibling('asa_dt_reconfigure', RECONFIGURE_FILENAMES)
RECONFIGURE_NAME = dt.__file__ and os.path.basename(dt.__file__)

Colors = dt.Colors
CiscoASA = dt.CiscoASA

OK = 'enabled'
OFF = 'disabled'
PARTIAL = 'partial'
ABSENT = 'absent'


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Report the status of the DT interface, NAT, ACL, egress "
                    "group and PAT configuration on a Cisco ASA.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--interface", default=dt.DEFAULT_INTERFACE)
    parser.add_argument("--nameif", default=dt.DEFAULT_NAMEIF)
    parser.add_argument("--object", dest="object_name", default=dt.DEFAULT_OBJECT)
    parser.add_argument("--sensor-nameif", default=dt.DEFAULT_SENSOR_NAMEIF)
    parser.add_argument("--acl", default=dt.DEFAULT_ACL)
    parser.add_argument("--pat-group", default=dt.DEFAULT_PAT_GROUP)
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON instead of a table")
    parser.add_argument("--verbose", action="store_true",
                        help="Echo raw console output")
    return parser.parse_args(argv)


def settings_from(args):
    """The subset of the reconfigure script's settings dict that the parsers need."""
    return {
        'interface': args.interface,
        'nameif': args.nameif,
        'object_name': args.object_name,
        'sensor_nameif': args.sensor_nameif,
        'acl_name': args.acl,
        'pat_group': args.pat_group,
    }


def snapshot(asa, settings):
    """
    Pull each running-config section exactly once. Serial round-trips are slow,
    and every check below can be answered from these five blocks.
    """
    return {
        'interface': asa.send_command(
            f"show running-config interface {settings['interface']}", timeout=15),
        'objects': asa.send_command('show running-config object network', timeout=20),
        'nat': dt.show_nat(asa),
        'acl': dt.show_acl(asa, settings['acl_name']),
        'groups': asa.send_command('show running-config object-group', timeout=20),
    }


def interface_status(config, settings):
    block = config['interface']
    address = dt.current_ip(block)
    network = None
    if address:
        try:
            network = str(ipaddress.IPv4Network(f"{address[0]}/{address[1]}",
                                                strict=False))
        except ValueError:
            network = None

    return {
        'name': settings['interface'],
        'present': bool(block),
        'nameif': (dt.re.search(r'^\s*nameif (\S+)', block or '', dt.re.MULTILINE)
                   or [None]) and _group1(block, r'^\s*nameif (\S+)'),
        'ip': address[0] if address else None,
        'netmask': address[1] if address else None,
        'network': network,
        'shutdown': dt.interface_is_shutdown(block),
    }


def _group1(text, pattern):
    match = dt.re.search(pattern, text or '', dt.re.MULTILINE)
    return match.group(1) if match else None


def object_status(config, settings, interface):
    block = dt.object_block(config['objects'], settings['object_name'])
    subnet = dt.current_subnet(block)
    matches = None
    if subnet and interface['network']:
        try:
            matches = (str(ipaddress.IPv4Network(f"{subnet[0]}/{subnet[1]}",
                                                 strict=False))
                       == interface['network'])
        except ValueError:
            matches = None

    return {
        'name': settings['object_name'],
        'present': bool(block),
        'subnet': f"{subnet[0]} {subnet[1]}" if subnet else None,
        'matches_interface': matches,
    }


def feature_status(config, settings, spec, members):
    """NAT + ACL + (for AGENT) egress membership for one of the NAT objects."""
    name = spec['object']
    nat = dt.object_nat_line(dt.object_block(config['nat'], name)) \
        or dt.object_nat_line(dt.object_block(config['objects'], name))
    ace = dt.find_acl_entry(config['acl'], settings, spec)
    in_group = name in members if spec.get('egress') else None

    parts = [nat is not None, ace is not None]
    if spec.get('egress'):
        parts.append(bool(in_group))

    if all(parts):
        state = OK
    elif not any(parts):
        state = OFF
    else:
        state = PARTIAL

    return {
        'name': name,
        'flag': spec['flag'],
        'state': state,
        'nat': nat,
        'nat_expected': dt.nat_line(settings, spec),
        'acl': ace,
        'acl_expected': dt.acl_line(settings, spec),
        'in_egress_group': in_group,
        'address': _group1(dt.object_block(config['objects'], name),
                           r'^\s*host (\S+)'),
    }


def egress_status(spec, members):
    """Group membership only, for LINDEF / WINDEF."""
    present = [n for n in spec['objects'] if n in members]
    missing = [n for n in spec['objects'] if n not in members]

    if not missing:
        state = OK
    elif not present:
        state = OFF
    else:
        state = PARTIAL

    return {
        'flag': spec['flag'],
        'state': state,
        'members_present': present,
        'members_missing': missing,
        'objects': spec['objects'],
    }


def pat_status(config, settings, interface):
    rule = dt.find_pat_rule(config['nat'], settings)
    described_ip = _group1(rule or '', r'behind (\d+\.\d+\.\d+\.\d+)')
    stale = None
    if rule and described_ip and interface['ip']:
        stale = described_ip != interface['ip']

    return {
        'state': OK if rule else OFF,
        'rule': rule,
        'described_ip': described_ip,
        'description_stale': stale,
    }


def build_report(config, settings):
    members = dt.group_members(
        dt.object_block(config['groups'], settings['pat_group'],
                        keyword='object-group network'))
    group_present = bool(dt.object_block(config['groups'], settings['pat_group'],
                                         keyword='object-group network'))

    interface = interface_status(config, settings)
    report = {
        'interface': interface,
        'object': object_status(config, settings, interface),
        'features': [feature_status(config, settings, spec, members)
                     for spec in dt.NAT_OBJECTS],
        'egress': [egress_status(spec, members) for spec in dt.EGRESS_MEMBERS],
        'pat': pat_status(config, settings, interface),
        'egress_group': {
            'name': settings['pat_group'],
            'present': group_present,
            'members': sorted(members),
        },
    }

    # The same rule the reconfigure script uses to decide the admin state.
    live = [f['name'] for f in report['features'] if f['nat']]
    if report['pat']['rule']:
        live.append('PAT')
    report['live_features'] = live
    report['expected_shutdown'] = not live

    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

MARK = {
    OK: (f"{Colors.GREEN}enabled {Colors.RESET}", '✓'),
    OFF: (f"{Colors.RESET}disabled{Colors.RESET}", '·'),
    PARTIAL: (f"{Colors.YELLOW}PARTIAL {Colors.RESET}", '!'),
    ABSENT: (f"{Colors.RED}absent  {Colors.RESET}", '✗'),
}


def render(report, settings):
    warnings = []
    interface = report['interface']

    print(f"\n{Colors.BOLD}DT status{Colors.RESET}")
    print("=" * 62)

    # ---- interface -------------------------------------------------------
    if not interface['present']:
        print(f"{Colors.RED}{interface['name']} not found in the running "
              f"config{Colors.RESET}")
        warnings.append(f"{interface['name']} does not exist on this device")
    else:
        admin = (f"{Colors.RED}SHUTDOWN{Colors.RESET}" if interface['shutdown']
                 else f"{Colors.GREEN}up{Colors.RESET}")
        address = (f"{interface['ip']} {interface['netmask']}"
                   if interface['ip'] else f"{Colors.YELLOW}no address{Colors.RESET}")
        print(f"  Interface   {interface['name']}  "
              f"nameif {interface['nameif'] or '-'}  [{admin}]")
        print(f"  Address     {address}")

    obj = report['object']
    if not obj['present']:
        print(f"  Object      {obj['name']}  {Colors.RED}not found{Colors.RESET}")
        warnings.append(f"object network {obj['name']} does not exist")
    else:
        note = ''
        if obj['matches_interface'] is False:
            note = f"  {Colors.YELLOW}(does not match the interface network){Colors.RESET}"
            warnings.append(
                f"{obj['name']} is {obj['subnet']} but {interface['name']} is on "
                f"{interface['network']} — re-run {RECONFIGURE_NAME} to realign them")
        print(f"  Object      {obj['name']}  {obj['subnet'] or '-'}{note}")

    # ---- features --------------------------------------------------------
    print("-" * 62)
    for feature in report['features']:
        label, glyph = MARK[feature['state']]
        print(f"  {glyph} {feature['name']:<10} {label}  ({feature['flag']})")
        print(f"      NAT      {_shorten(feature['nat'])}")
        print(f"      ACL      {_shorten(feature['acl'])}")
        if feature['in_egress_group'] is not None:
            member = 'yes' if feature['in_egress_group'] else 'no'
            print(f"      egress   {member}")

        if feature['state'] == PARTIAL:
            if feature['nat'] and not feature['acl']:
                warnings.append(f"{feature['name']} has NAT but no {settings['acl_name']} "
                                f"entry — traffic is translated then dropped")
            elif feature['acl'] and not feature['nat']:
                warnings.append(f"{feature['name']} has an ACL entry but no NAT")
            elif feature['in_egress_group'] is False:
                warnings.append(f"{feature['name']} is configured but not a member "
                                f"of {settings['pat_group']}")
        if feature['nat'] and feature['nat'] != feature['nat_expected']:
            warnings.append(f"{feature['name']} NAT differs from the expected rule "
                            f"({feature['nat']})")
        if feature['acl'] and feature['acl'] != feature['acl_expected']:
            warnings.append(f"{feature['name']} ACL entry differs from the expected "
                            f"rule ({feature['acl']})")

    # ---- egress group ----------------------------------------------------
    print("-" * 62)
    group = report['egress_group']
    if not group['present']:
        print(f"  {Colors.RED}object-group network {group['name']} not "
              f"found{Colors.RESET}")
        warnings.append(f"object-group network {group['name']} does not exist")
    else:
        print(f"  Group       {group['name']}  "
              f"({len(group['members'])} member"
              f"{'' if len(group['members']) == 1 else 's'})")
        for entry in report['egress']:
            label, glyph = MARK[entry['state']]
            detail = ', '.join(entry['members_present']) or '-'
            print(f"  {glyph} {entry['flag']:<10} {label}  {detail}")
            if entry['state'] == PARTIAL:
                warnings.append(f"{entry['flag']} is partial — missing "
                                f"{', '.join(entry['members_missing'])}")
        extra = set(group['members']) - _all_known(report)
        if extra:
            print(f"      other    {', '.join(sorted(extra))}")

    # ---- PAT -------------------------------------------------------------
    print("-" * 62)
    pat = report['pat']
    label, glyph = MARK[pat['state']]
    print(f"  {glyph} PAT        {label}  (--pat)")
    print(f"      rule     {_shorten(pat['rule'], 90)}")
    if pat['description_stale']:
        warnings.append(f"the PAT description still names {pat['described_ip']} but "
                        f"the interface is {interface['ip']}")

    # ---- posture ---------------------------------------------------------
    print("=" * 62)
    live = report['live_features']
    if live:
        print(f"  Live: {', '.join(live)}")
    else:
        print("  Live: nothing enabled")

    if interface['present']:
        if report['expected_shutdown'] and not interface['shutdown']:
            warnings.append(f"no features are enabled but {interface['name']} is up — "
                            f"{RECONFIGURE_NAME} would shut it")
        elif live and interface['shutdown']:
            warnings.append(f"{interface['name']} is shut down but {', '.join(live)} "
                            f"{'is' if len(live) == 1 else 'are'} configured — "
                            f"that traffic is not flowing")

    if warnings:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Attention{Colors.RESET}")
        for item in warnings:
            print(f"  {Colors.YELLOW}!{Colors.RESET} {item}")
    else:
        print(f"\n{Colors.GREEN}Everything is internally consistent.{Colors.RESET}")

    return warnings


def _all_known(report):
    known = {f['name'] for f in report['features']}
    for entry in report['egress']:
        known.update(entry['objects'])
    return known


def _shorten(text, width=70):
    if not text:
        return f"{Colors.RESET}—{Colors.RESET}"
    return text if len(text) <= width else text[:width - 1] + '…'


def main():
    args = parse_args()
    settings = settings_from(args)

    asa = None
    try:
        asa = CiscoASA(verbose=args.verbose)
        if not asa.connect():
            dt.error("Failed to connect to ASA")
            return 1

        auth_secret = (os.getenv('ASA_SECRET')
                       or os.getenv('ASA_KNOWN_SECRET', 'Cisco123'))
        if not dt.enter_enable(asa, auth_secret):
            return 1
        dt.restore_pager(asa)

        config = snapshot(asa, settings)
        report = build_report(config, settings)

        if args.json:
            print(json.dumps(report, indent=2))
            return 0

        warnings = render(report, settings)
        # Exit 2 on inconsistency so a wrapper can act on it; 0 when clean.
        return 2 if warnings else 0

    except KeyboardInterrupt:
        return 130
    except Exception as e:
        dt.error(f"Failed: {e}")
        return 1
    finally:
        if asa:
            asa.disconnect()


if __name__ == "__main__":
    sys.exit(main())
