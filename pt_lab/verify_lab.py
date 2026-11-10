"""Offline checks only; passing does NOT prove Packet Tracer compatibility."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET

from pkt_core import decode, encode_bytes
from pkt_core.builder import load_templates
from pkt_core.cli.main import main as pkt_main
from pkt_core.models import Lab

from build_lab import (
    DEFAULT_OUTPUT, DEVICES, IPV4_HOSTS, LINKS, ROUTERS, SERVICE_TAGS,
    port_inventory, running_config, switch_config,
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalized(lines):
    return [s.strip() for s in lines if s.strip() and not s.strip().startswith("!")]


def cli(args):
    print("\n$ pkt " + " ".join(map(str, args)))
    result = pkt_main(list(map(str, args)))
    require(result == 0, f"pkt command failed with exit code {result}")


def verify(path, no_tunnels=False):
    cli(["info", path])
    container = decode(path)
    require(container.root_tag == "PACKETTRACER5" and not container.is_activity, "Wrong document root/type")
    require(encode_bytes(container.xml, container.format_name) == path.read_bytes(), "Byte-exact container round trip failed")
    print("PASS: root PACKETTRACER5; byte-exact encode(decode(file)) == file")
    lab = Lab.from_bytes(container.xml)
    print(f"Typed model: {len(lab.devices)} devices, {len(lab.links)} links; PT seed version {lab.version}")
    print("Specification correction: links table = 9 island + 3 uplink + 4 ring + 4 server = 20, not 25.")
    require(len(lab.devices) == len(DEVICES) == 20, "Device count mismatch")
    require(len(lab.links) == len(LINKS) == 20, "Link count mismatch against links table")
    names = [d.name for d in lab.devices]
    require(len(names) == len(set(names)), "Duplicate device names")
    root = ET.fromstring(container.xml)
    devices = root.findall("NETWORK/DEVICES/DEVICE")
    by_name = {d.findtext("ENGINE/NAME"): d for d in devices}
    by_id = {d.findtext("ENGINE/SAVE_REF_ID"): name for name, d in by_name.items()}
    require(len(by_id) == 20 and None not in by_id, "Duplicate/missing SAVE_REF_ID")
    require(set(by_name) == {d[0] for d in DEVICES}, "Unexpected/seed device present")
    models, _ = load_templates()
    inventories = {}
    for name, model, x, y in DEVICES:
        device = by_name[name]
        require(device.find("ENGINE/TYPE").get("model") == model, f"Wrong model: {name}")
        require((float(device.findtext("WORKSPACE/LOGICAL/X")), float(device.findtext("WORKSPACE/LOGICAL/Y"))) == (x, y), f"Wrong position: {name}")
        inventories[name], _ = port_inventory(device, ET.fromstring(models[model]))
        require(device.findtext("ENGINE/POWER") == "true", f"Device is not powered: {name}")
        require(device.findtext("ENGINE/SYS_NAME") == name, f"Stale SYS_NAME: {name}")
        eng = device.find("ENGINE")
        for block in eng:
            if block.tag in SERVICE_TAGS:
                for e in block.iter():
                    if e.tag in {"ENABLED", "HTTPSENABLED", "SMTP_ENABLED", "POP3_ENABLED"}:
                        require((e.text or "0") == "0", f"Inherited service enabled: {name}:{block.tag}")
        if name in ROUTERS or model == "2960-24TT":
            expected = running_config(name, no_tunnels) if name in ROUTERS else switch_config(name)
            for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
                blocks = eng.findall(tag)
                require(len(blocks) == 1, f"Missing/duplicate {tag}: {name}")
                actual = [s.text or "" for s in blocks[0].findall("LINE")]
                require(actual == expected, f"{tag} differs from authored config: {name}")
                require(f"hostname {name}" in actual, f"Stale hostname: {name}")
            if name.startswith("NAT"):
                require(any(s.startswith("ipv6 nat v6v4 pool ") for s in actual), f"Missing NAT pool: {name}")
                require(any(s.startswith("interface Tunnel") for s in actual) == (not no_tunnels), f"Tunnel presence mismatch: {name}")
                interface = None
                for line in actual:
                    if line.startswith("interface "):
                        interface = line.split()[1]
                    elif line == "!":
                        interface = None
                    if interface and interface.startswith("Tunnel"):
                        require(line.strip() != "ipv6 nat", "NAT enabled on tunnel")
            elif name in ROUTERS:
                require("router ospf 1" in actual, f"Missing OSPF: {name}")
        else:
            require(eng.find("RUNNINGCONFIG") is None and eng.find("STARTUPCONFIG") is None, f"Inherited host IOS config: {name}")
        # Check all actual NICs, not just linked ones, for inherited addresses.
        for port in inventories[name].values():
            if name in IPV4_HOSTS:
                require(tuple(port.findtext(t, "") for t in ("IP", "SUBNET", "PORT_GATEWAY")) == IPV4_HOSTS[name], f"Wrong IPv4 settings: {name}")
            else:
                require(all(not port.findtext(t, "") for t in ("IP", "SUBNET", "PORT_GATEWAY", "PORT_DNS")), f"Phantom NIC IPv4 address: {name}")
            require(port.findtext("PORT_DHCP_ENABLE") == "false", f"DHCP enabled: {name}")
            addresses = port.find("IPV6_ADDRESSES")
            if addresses is not None:
                require(not list(addresses), f"Inherited IPv6 addresses: {name}")
        require(eng.findtext("GATEWAY", "") == (IPV4_HOSTS[name][2] if name in IPV4_HOSTS else ""), f"Stale engine gateway: {name}")
    actual_links, used = [], set()
    for link in root.findall("NETWORK/LINKS/LINK"):
        cable = link.find("CABLE")
        require(cable is not None, "Missing cable")
        ports = [p.text for p in cable.findall("PORT")]
        require(len(ports) == 2, "Wrong cable port count")
        a, b = by_id.get(cable.findtext("FROM")), by_id.get(cable.findtext("TO"))
        require(a is not None and b is not None, "Dangling cable endpoint")
        endpoints = ((a, ports[0]), (b, ports[1]))
        for name, port in endpoints:
            require(port in inventories[name], f"Port missing on actual instance: {name}:{port}")
            require((name, port) not in used, f"Port used twice: {name}:{port}")
            require(inventories[name][port].findtext("POWER") == "true", f"Unpowered linked port: {name}:{port}")
            used.add((name, port))
        actual_links.append(tuple(sorted(endpoints)))
        expected_cable = "eCrossOver" if a in ROUTERS and b in ROUTERS else "eStraightThrough"
        require(link.findtext("TYPE") == "eCopper" and cable.findtext("TYPE") == expected_cable, "Wrong copper cable type")
    expected_links = [tuple(sorted(((a, ap), (b, bp)))) for a, ap, b, bp in LINKS]
    require(Counter(actual_links) == Counter(expected_links), "Endpoints do not match the requested links table exactly")
    for tag in ("MACADDRESS", "BIA"):
        values = [e.text for d in devices for e in d.iter(tag) if e.text]
        require(len(values) == len(set(values)), f"Duplicate {tag}")
    uuids = {n.findtext("UUID_STR") for n in root.findall("PHYSICALWORKSPACE//NODE")}
    leaves = []
    for d in devices:
        physical = d.find("WORKSPACE/PHYSICAL")
        require(physical is not None and not physical.attrib, "Invalid physical path attributes")
        parts = physical.text.split(",")
        require(all(p in uuids and p.startswith("{") and p.endswith("}") for p in parts), "Unresolved/unbraced physical UUID")
        leaves.append(parts[-1])
        require(d.find("WORKSPACE/PHYSICAL_CPUR") is not None, "Missing physical CPUR")
    require(len(leaves) == len(set(leaves)), "Shared physical device leaves")
    print("PASS: 20 distinct names/models/positions; 20 distinct exact cables; 40 unique powered endpoints")
    print("PASS: authored running/startup configs, NAT-PT/OSPF/tunnels, blank IPv6-host IPv4, static IPv4 hosts, unique MACs and physical leaves")
    temp_base = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "Temp" / "opencode"
    temp_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pkt-unpack-", dir=temp_base) as temp:
        cli(["unpack", path, "-o", temp])
        for name in ROUTERS:
            extracted = (Path(temp) / "configs" / f"{name}.cfg").read_text(encoding="utf-8").splitlines()
            require(normalized(extracted) == normalized(running_config(name, no_tunnels)), f"Unpacked IOS mismatch: {name}")
    print("PASS: all 7 unpacked router configs match paste-ready sources after EXEC/exit/indent/comment normalization")
    cli(["audit", path, "--templates", Path(__import__("pkt_core").__file__).parent / "data" / "device_templates.json"])
    print("SHA256: " + hashlib.sha256(path.read_bytes()).hexdigest())
    print("OFFLINE VERIFICATION PASSED. Not opened/tested in Packet Tracer; IOS acceptance and traffic remain unverified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--no-tunnels", action="store_true", help="Expect an artifact built with --no-tunnels")
    parser.add_argument("--report", type=Path, help="Also write complete verification output to a text file")
    args = parser.parse_args()
    capture = io.StringIO()
    error = None
    try:
        with redirect_stdout(capture):
            verify(args.file, args.no_tunnels)
    except Exception as exc:
        error = exc
        capture.write(f"FAILED: {exc}\n")
    text = capture.getvalue()
    print(text, end="")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
