"""Generate FortiOS IPv4 CLI drafts and an H3C migration report."""

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import os
from pathlib import Path
import re
import sys


@dataclass(frozen=True)
class Line:
    number: int
    text: str

    @property
    def words(self):
        return self.text.split()


def read_config(path, encoding):
    return decode_config(path.read_bytes(), encoding)


def decode_config(data, encoding="auto"):
    if encoding != "auto":
        return data.decode(encoding), encoding, []
    for codec in ("utf-8-sig", "gb18030"):
        try:
            return data.decode(codec), codec, []
        except UnicodeDecodeError:
            continue
    decoded = []
    replacements = []
    for number, raw in enumerate(data.removeprefix(b"\xef\xbb\xbf").splitlines(), 1):
        for codec in ("utf-8", "gb18030"):
            try:
                decoded.append(raw.decode(codec))
                break
            except UnicodeDecodeError:
                continue
        else:
            decoded.append(raw.decode("gb18030", errors="replace"))
            replacements.append(number)
    return "\n".join(decoded), "mixed UTF-8/GB18030", replacements


def blocks(config):
    block = []
    for number, raw in enumerate(config.splitlines(), 1):
        command = raw.strip()
        if command == "#" or (command and not raw[0].isspace() and block):
            if block:
                yield block
            block = []
        if command and command != "#":
            block.append(Line(number, command))
    if block:
        yield block


def rule_blocks(lines):
    header = None
    commands = []
    for line in lines:
        if line.words[0] == "rule":
            if header:
                yield header, commands
            header, commands = line, []
        elif header:
            commands.append(line)
        else:
            yield line, []
    if header:
        yield header, commands


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ipv4(value):
    require(re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", value), "expected dotted IPv4 address")
    return IPv4Address(value)


def mask_prefix(mask):
    if re.fullmatch(r"[0-9]{1,2}", mask):
        require(int(mask) <= 32, "invalid IPv4 prefix length")
        return int(mask)
    ipv4(mask)
    net = IPv4Network(f"0.0.0.0/{mask}")
    require(str(net.netmask) == mask, "expected a contiguous IPv4 netmask")
    return net.prefixlen


def network(address, mask):
    return IPv4Network((ipv4(address), mask_prefix(mask)), strict=False)


def addr_spec(kind, values):
    match kind, values:
        case "host", [host]:
            return ("subnet", str(ipv4(host)), "255.255.255.255")
        case "subnet", [address, mask]:
            net = network(address, mask)
            return ("subnet", str(net.network_address), str(net.netmask))
        case "range", [first, last]:
            low, high = ipv4(first), ipv4(last)
            require(low <= high, "reversed IPv4 range")
            return ("iprange", str(low), str(high))
        case _:
            raise ValueError("unsupported IPv4 address form")


def target_name(kind, source, limit):
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", source).strip("_") or "item"
    digest = sha256(source.encode("utf-8")).hexdigest()[:10]
    prefix = f"h3c-{kind}-"
    return f"{prefix}{stem[:limit - len(prefix) - len(digest) - 1]}-{digest}"


def quoted(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cli_values(values):
    return " ".join(quoted(value) for value in dict.fromkeys(values))


class Draft:
    def __init__(self):
        self.tables = defaultdict(dict)

    def add(self, table, key, commands):
        entries = self.tables[table]
        require(key not in entries or entries[key] == commands, "duplicate CLI entry")
        entries[key] = commands

    def address(self, source, spec):
        name = target_name("a", source, 63)
        kind, first, last = spec
        commands = (["set type iprange", f"set start-ip {first}", f"set end-ip {last}"]
                    if kind == "iprange" else [f"set subnet {first} {last}"])
        self.add("firewall address", name, commands)
        return name

    def render(self):
        result = []
        for table in ("firewall address", "firewall addrgrp", "firewall service custom",
                      "router static", "firewall policy"):
            if not self.tables[table]:
                continue
            result.append(f"config {table}")
            for key, commands in self.tables[table].items():
                result.append(f"    edit {quoted(key) if isinstance(key, str) else key}")
                result.extend(f"        {command}" for command in commands)
                result.append("    next")
            result.extend(("end", ""))
        return "\n".join(result) + ("\n" if result else "")


def parse_address(lines):
    members = []
    zone = None
    for line in lines:
        match line.words:
            case ["description", *_] | ["object", _, "description", *_]:
                continue
            case ["security-zone", name] if zone is None:
                zone = name
            case [index, "network", "host", "address", host] if index.isdecimal():
                members.append(addr_spec("host", [host]))
            case [index, "network", kind, *values] if index.isdecimal() and kind in {"subnet", "range"}:
                members.append(addr_spec(kind, values))
            case _:
                raise ValueError(f"unsupported address member at line {line.number}")
    require(members, "empty IPv4 address group")
    return list(dict.fromkeys(members)), zone


def parse_service(lines):
    ports = defaultdict(set)
    for line in lines:
        match line.words:
            case ["description", *_] | ["object", _, "description", *_]:
                continue
            case [index, "service", proto, "destination", operator, *values] if (
                    index.isdecimal() and proto in {"tcp", "udp"}):
                require((operator, len(values)) in {("eq", 1), ("range", 2)}
                        and all(re.fullmatch(r"[0-9]{1,5}", value) for value in values),
                        f"unsupported destination port at line {line.number}")
                start, end = int(values[0]), int(values[-1])
                require(1 <= start <= end <= 65535, f"invalid port range at line {line.number}")
                ports[proto].add((start, end))
            case _:
                raise ValueError(f"unsupported service member at line {line.number}")
    require(ports, "empty service group")
    return {proto: [str(a) if a == b else f"{a}-{b}" for a, b in sorted(ranges)]
            for proto, ranges in sorted(ports.items())}


def parse_pool(lines):
    ranges = []
    for line in lines:
        match line.words:
            case ["address", first, last]:
                _, start, end = addr_spec("range", [first, last])
                ranges.append([start, end])
            case _:
                raise ValueError(f"unsupported NAT pool command at line {line.number}")
    require(ranges, "empty NAT address pool")
    return ranges


def inventory_interface(lines):
    result = {"line": lines[0].number, "ipv4": [], "aggregation_member": None,
              "layer2": lines[0].words[-1].startswith("Bridge-Aggregation"), "dhcp": False,
              "shutdown": False}
    for line in lines[1:]:
        match line.words:
            case ["ip", "address", "dhcp-alloc"]:
                result["dhcp"] = True
            case ["ip", "address", address, mask] | ["ip", "address", address, mask, "sub"]:
                try:
                    result["ipv4"].append(str(IPv4Interface(f"{ipv4(address)}/{mask_prefix(mask)}")))
                except ValueError:
                    result["ipv4_errors"] = True
            case ["ip", "address", *_]:
                result["ipv4_errors"] = True
            case ["port", "link-mode", "bridge"] | ["port", "link-type", *_] | ["port", "access", "vlan", *_]:
                result["layer2"] = True
            case ["port", "link-aggregation", "group", group]:
                result["aggregation_member"] = group
            case ["shutdown"]:
                result["shutdown"] = True
    return result


def inventory_zone(lines):
    members = []
    for line in lines[1:]:
        match line.words:
            case ["import", "interface", interface, *qualifier]:
                members.append({"interface": interface, "qualifier": " ".join(qualifier)})
    return {"line": lines[0].number, "members": members}


def route_distance(value):
    require(re.fullmatch(r"[0-9]{1,3}", value), "invalid route preference")
    distance = int(value)
    require(1 <= distance <= 254, "route preference outside usable FortiOS distance range")
    return distance


def parse_route(line, default_distance):
    words = line.words[2:]
    require(len(words) >= 3, "incomplete static route")
    subnet = network(*words[:2])
    next_hop = words[2]
    interface = None
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", next_hop):
        interface, words = next_hop, words[1:]
        require(len(words) >= 3, "interface-only or unsupported static route")
        next_hop = words[2]
    gateway = str(ipv4(next_hop))
    require(gateway != "0.0.0.0", "zero next hop requires manual mapping")
    distance = default_distance
    options = words[3:]
    if options[:1] == ["preference"]:
        require(len(options) >= 2, "missing route preference")
        distance = route_distance(options[1])
        options = options[2:]
    require(distance is not None, "source default route preference requires review")
    require(not options or options[0] == "description", "unsupported static route options")
    return {"destination": str(subnet), "gateway": gateway, "interface": interface,
            "distance": distance}


def resolve_route(route, interfaces, interface_map):
    if route["interface"] is None:
        gateway = ipv4(route["gateway"])
        connected = []
        for name, interface in interfaces.items():
            if (interface["layer2"] or interface["aggregation_member"] or interface["shutdown"]
                    or interface.get("ipv4_errors")):
                continue
            for value in interface["ipv4"]:
                addr = IPv4Interface(value)
                if gateway != addr.ip and gateway in addr.network:
                    connected.append((addr.network.prefixlen, name))
        require(connected, "next hop is not on a known connected IPv4 subnet")
        best = max(length for length, _ in connected)
        matches = {name for length, name in connected if length == best}
        require(len(matches) == 1, "ambiguous connected interface for next hop")
        route["interface"] = matches.pop()
        route["interface_inferred"] = True
    require(route["interface"] in interface_map, "missing target interface mapping")
    return interface_map[route["interface"]]


def selector(command, values, nat):
    if nat and values[0] in {"host", "subnet", "range"} and len(values) > 1:
        return addr_spec(values[0], values[1:])
    if not nat and command.endswith(("-host", "-subnet", "-range")):
        return addr_spec(command.rsplit("-", 1)[1], values)
    require(len(values) == 1, "unsupported address reference")
    return ("object", values[0])


def rule_identity(header, nat):
    if nat:
        require(header.words[:2] == ["rule", "name"] and len(header.words) >= 3,
                "unsupported NAT rule header")
    else:
        require(len(header.words) >= 4 and header.words[0] == "rule"
                and header.words[1].isdecimal() and header.words[2] == "name",
                "unsupported security rule header")
    identity = {"name": header.text.split(maxsplit=2 if nat else 3)[-1]}
    if not nat:
        identity["source_id"] = int(header.words[1])
    return identity


def parse_rule(lines, nat, addresses, services, zones, pools):
    rule = {"enabled": True, "source_zones": [], "destination_zones": [],
            "source_addresses": [], "destination_addresses": [], "services": [], "logging": None}
    for line in lines:
        command, *values = line.words
        try:
            match command, values:
                case "disable", [] if rule["enabled"]:
                    rule["enabled"] = False
                case "logging", [state] if state in {"enable", "disable"} and rule["logging"] is None:
                    rule["logging"] = state == "enable"
                case "counting", ["enable" | "disable"]:
                    pass
                case "description", [*_]:
                    pass
                case "source-zone" | "destination-zone", [zone]:
                    require(zone in zones, "undefined security zone reference")
                    side = command.split("-", 1)[0]
                    rule[f"{side}_zones"].append(zone)
                case "service", [name]:
                    require(name in services, "unsupported or undefined service reference")
                    rule["services"].append(name)
                case "action", [action, *args] if "action" not in rule:
                    if nat and action == "dnat" and len(args) in {2, 4} and args[0] == "ip-address":
                        rule["mapped_ip"] = str(ipv4(args[1]))
                        if len(args) == 4:
                            require(args[2] == "local-port" and re.fullmatch(r"[0-9]{1,5}", args[3])
                                    and 1 <= int(args[3]) <= 65535, "unsupported local NAT port")
                            rule["mapped_port"] = int(args[3])
                    elif nat and action == "snat" and len(args) == 2 and args[0] == "address-group":
                        require(args[1] in pools, "undefined NAT address pool")
                        rule["pool"] = args[1]
                    else:
                        require(not nat and action in {"pass", "drop"} and not args,
                                "unsupported rule action")
                    rule["action"] = action
                case _, [*_] if values and command in {
                    "source-ip", "destination-ip", "source-ip-host", "destination-ip-host",
                    "source-ip-subnet", "destination-ip-subnet", "source-ip-range", "destination-ip-range"
                } and (not nat or command in {"source-ip", "destination-ip"}):
                    side = command.split("-", 1)[0]
                    spec = selector(command, values, nat)
                    if spec[0] == "object":
                        require(spec[1] in addresses, "unsupported or undefined address reference")
                    rule[f"{side}_addresses"].append(spec)
                case _:
                    raise ValueError("unsupported rule command")
        except ValueError as error:
            raise ValueError(f"line {line.number}: {error}") from error
    require("action" in rule, "missing rule action")
    return rule


def add_policy(draft, rule, zone_map, addresses, services, first_id, ordinal):
    require(all(zone.lower() != "local" for zone in
                rule["source_zones"] + rule["destination_zones"]),
            "Local traffic requires local-in/local-out review")
    for side in ("source", "destination"):
        names = rule[f"{side}_zones"]
        require(names, "implicit any-zone match requires manual review")
        require(all(name in zone_map for name in names), "missing target zone mapping")
        for spec in rule[f"{side}_addresses"]:
            if spec[0] == "object":
                zone = addresses[spec[1]]["source_zone"]
                require(zone is None or set(names) == {zone},
                        "zone-bound address used outside a single matching zone")
    commands = ["set status disable", f'set name {quoted(target_name("p", rule["name"], 35))}']
    for side, short in (("source", "src"), ("destination", "dst")):
        commands.append(f'set {short}intf {cli_values(zone_map[name] for name in rule[f"{side}_zones"])}')
        names = []
        for spec in rule[f"{side}_addresses"]:
            if spec[0] == "object":
                names.append(addresses[spec[1]]["target"])
            else:
                names.append(draft.address("inline:" + ":".join(spec), spec))
        commands.append(f'set {short}addr {cli_values(names or ["all"])}')
    commands += [
        f'set action {"accept" if rule["action"] == "pass" else "deny"}',
        'set schedule "always"',
        f'set service {cli_values([services[name]["target"] for name in rule["services"]] or ["ALL"])}',
        f'set logtraffic {"all" if rule["logging"] else "disable"}',
    ]
    if rule["action"] == "pass":
        commands.append("set nat disable")
    target_id = first_id + ordinal
    draft.add("firewall policy", target_id, commands)
    return target_id


def read_mapping(path):
    if path is None:
        return {}, {}

    def unique_object(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "duplicate JSON mapping key")
        return result

    return validate_mapping(json.loads(path.read_text(encoding="utf-8-sig"),
                                       object_pairs_hook=unique_object))


def validate_mapping(data):
    require(isinstance(data, dict) and data.keys() <= {"interfaces", "zones"},
            "mapping must contain only interfaces and/or zones")
    for key in ("interfaces", "zones"):
        mapping = data.get(key, {})
        require(isinstance(mapping, dict), f"{key} must be an object")
        require(all(src.strip() == src and src and isinstance(dst, str)
                    and re.fullmatch(r"[A-Za-z0-9_.:-]{1,35}", dst)
                    and dst.lower() not in {"all", "any"} for src, dst in mapping.items()),
                f"invalid {key} mapping name")
        require(len({value.casefold() for value in mapping.values()}) == len(mapping),
                f"multiple {key} entries map to the same target")
    interface_map, zone_map = data.get("interfaces", {}), data.get("zones", {})
    require(not ({name.casefold() for name in interface_map.values()}
                 & {name.casefold() for name in zone_map.values()}),
            "a target name cannot be both a zone and a routed interface")
    return interface_map, zone_map


def translate(config, interface_map, zone_map, route_start, policy_start):
    draft = Draft()
    sections = list(blocks(config))
    require(sum(section[0].words[0] == "context" for section in sections) <= 1,
            "multiple context declarations require extraction into separate inputs")
    interfaces, zones, addresses, services, pools = {}, {}, {}, {}, {}
    report = {
        "source_version": None, "interfaces": interfaces, "zones": zones, "addresses": addresses,
        "services": services, "nat_pools": pools, "routes": [], "policies": [], "nat_rules": [],
        "unconverted_sections": {}, "issues": [], "inventory": {},
    }
    counts = Counter()
    unconverted = Counter()
    route_lines, preferences, policy_blocks, nat_blocks = [], [], [], []
    objects = {"address": [], "service": [], "nat_pool": []}

    for section in sections:
        head, *body = section
        match head.words:
            case ["version", *_]:
                report["source_version"] = head.text.removeprefix("version ")
            case ["object-group", "ip", "address", name]:
                objects["address"].append((name, head, body))
            case ["object-group", "service", name]:
                objects["service"].append((name, head, body))
            case ["nat", "address-group", name]:
                objects["nat_pool"].append((name, head, body))
            case ["interface", name]:
                require(name not in interfaces, f"duplicate interface at line {head.number}")
                interfaces[name] = inventory_interface(section)
            case ["security-zone", "name", name]:
                require(name not in zones, f"duplicate zone at line {head.number}")
                zones[name] = inventory_zone(section)
            case ["ip", "route-static", *_]:
                for line in section:
                    match line.words:
                        case ["ip", "route-static", "default-preference", *values]:
                            preferences.append((line.number, values))
                        case ["ip", "route-static", *_]:
                            route_lines.append(line)
                        case _:
                            report["issues"].append({"line": line.number, "category": "route",
                                                     "reason": "unrecognized line in route section"})
            case ["security-policy", "ip"]:
                policy_blocks.extend(rule_blocks(body))
            case ["nat", "global-policy"]:
                nat_blocks.extend(rule_blocks(body))
            case ["traffic-policy"]:
                counts["qos_rules"] += sum(line.words[0] == "rule" for line in body)
                counts["qos_profiles"] += sum(line.words[:2] == ["profile", "name"] for line in body)
                unconverted["traffic-policy"] += 1
            case _:
                label = head.words[0]
                if label == "acl":
                    counts["acl_rules"] += sum(line.words[0] == "rule" for line in body)
                unconverted[label] += 1

    require(interface_map.keys() <= interfaces.keys(), "mapping contains unknown H3C interfaces")
    require(zone_map.keys() <= zones.keys(), "mapping contains unknown H3C zones")
    for key, records in objects.items():
        counts[key + "_groups"] = len(records)
        names = Counter(name for name, _, _ in records)
        for name, head, body in records:
            try:
                require(names[name] == 1, "duplicate source object name")
                if key == "address":
                    specs, zone = parse_address(body)
                    if len(specs) == 1:
                        target = draft.address("group:" + name, specs[0])
                    else:
                        target = target_name("g", name, 63)
                        members = [
                            draft.address(f"member:{name}:{index}", spec)
                            for index, spec in enumerate(specs, 1)
                        ]
                        draft.add("firewall addrgrp", target, [f"set member {cli_values(members)}"])
                    addresses[name] = {"line": head.number, "target": target, "members": specs,
                                       "source_zone": zone}
                elif key == "service":
                    ports = parse_service(body)
                    target = target_name("s", name, 63)
                    commands = [f'set {proto}-portrange {" ".join(values)}'
                                for proto, values in ports.items()]
                    draft.add("firewall service custom", target, commands)
                    services[name] = {"line": head.number, "target": target, "ports": ports}
                else:
                    pools[name] = {"line": head.number, "ranges": parse_pool(body)}
            except ValueError as error:
                report["issues"].append({"line": head.number, "category": key, "reason": str(error)})

    default_distance = 60
    if preferences:
        number, values = preferences[0]
        try:
            require(len(preferences) == 1 and len(values) == 1,
                    "ambiguous source default route preference")
            default_distance = route_distance(values[0])
        except ValueError as error:
            default_distance = None
            report["issues"].append({"line": number, "category": "route", "reason": str(error)})
    report["source_default_static_preference"] = default_distance
    for ordinal, line in enumerate(route_lines):
        item = {"line": line.number, "status": "manual"}
        try:
            item.update(parse_route(line, default_distance))
            device = resolve_route(item, interfaces, interface_map)
            net = IPv4Network(item["destination"])
            target_id = route_start + ordinal
            draft.add("router static", target_id, [
                "set status disable", f"set dst {net.network_address} {net.netmask}",
                f'set gateway {item["gateway"]}', f"set device {quoted(device)}",
                f'set distance {item["distance"]}',
            ])
            item.update(status="cli_disabled", target_id=target_id, target_interface=device)
        except ValueError as error:
            item["reason"] = str(error)
        report["routes"].append(item)

    for is_nat, records, output in ((False, policy_blocks, "policies"), (True, nat_blocks, "nat_rules")):
        identities = Counter(
            (head.text.split(maxsplit=2)[-1] if is_nat else int(head.words[1]))
            for head, _ in records if len(head.words) >= 3
            and head.words[0] == "rule" and (is_nat or head.words[1].isdecimal())
        )
        for ordinal, (header, body) in enumerate(records):
            item = {"line": header.number, "status": "manual"}
            try:
                item.update(rule_identity(header, is_nat))
                key = item["name"] if is_nat else item["source_id"]
                require(identities[key] == 1, "duplicate source rule identity")
                item.update(parse_rule(body, is_nat, addresses, services, zones, pools))
                if is_nat:
                    item["status"] = "nat_review"
                    item["reason"] = "confirm NAT evaluation order, policy linkage and target NAT mode"
                else:
                    item["target_id"] = add_policy(
                        draft, item, zone_map, addresses, services, policy_start, ordinal)
                    item["status"] = "cli_disabled"
            except ValueError as error:
                item["reason"] = str(error)
            report[output].append(item)

    counts.update(interfaces=len(interfaces), zones=len(zones), routes=len(route_lines),
                  policies=len(policy_blocks), nat_rules=len(nat_blocks))
    report["inventory"] = dict(counts)
    report["unconverted_sections"] = dict(sorted(unconverted.items()))
    report["cli_entries"] = {table: len(entries) for table, entries in draft.tables.items() if entries}
    return draft.render(), report


def convert_config(source, encoding, replacements, interface_map, zone_map,
                   route_start=10000, policy_start=10000):
    require(1 <= route_start <= 2147483647 and 1 <= policy_start <= 2147483647,
            "output ID must be between 1 and 2147483647")
    cli, report = translate(source, interface_map, zone_map, route_start, policy_start)
    require(any(report["inventory"].values()), "no supported H3C configuration sections found")
    require(route_start + report["inventory"]["routes"] - 1 <= 2147483647
            and policy_start + report["inventory"]["policies"] - 1 <= 2147483647,
            "generated IDs exceed FortiOS numeric range")
    report.update(source_encoding=encoding, encoding_replacement_lines=replacements)
    return cli, report


def write_outputs(files):
    created = []
    try:
        for path, content in files:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                output.write(content)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="H3C configuration export")
    parser.add_argument("--cli", required=True, type=Path, help="output FortiOS CLI text")
    parser.add_argument("--report", required=True, type=Path, help="output JSON report")
    parser.add_argument("--mapping", type=Path, help="JSON mapping for existing target interfaces and zones")
    parser.add_argument("--encoding", default="auto", help="source encoding, default auto")
    parser.add_argument("--route-start", type=int, default=10000, help="first candidate static route ID")
    parser.add_argument("--policy-start", type=int, default=10000, help="first candidate policy ID")
    args = parser.parse_args()
    try:
        paths = [args.source, args.cli, args.report] + ([args.mapping] if args.mapping else [])
        require(len(set(path.resolve() for path in paths)) == len(paths),
                "source, mapping and output paths must be distinct")
        require(not args.cli.exists() and not args.report.exists(), "output files already exist")
        cli, report = convert_config(*read_config(args.source, args.encoding),
                                     *read_mapping(args.mapping), args.route_start, args.policy_start)
        report_text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        write_outputs(((args.cli, cli), (args.report, report_text)))
    except (OSError, ValueError, LookupError) as error:
        print(f"translation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
