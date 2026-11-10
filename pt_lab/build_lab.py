"""Author a plain .pkt using packet-tracer-pkt-format, never custom crypto."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from pkt_core.audit import sanitize_engine
from pkt_core.builder import Lab, load_templates

HERE = Path(__file__).resolve().parent
DEFAULT_OUTPUT = HERE / "NAT64_lab.pkt"
DEVICES = [
    ("C1", "2911", 350, 150), ("C2", "2911", 350, 450),
    ("C3", "2911", 650, 450), ("C4", "2911", 650, 150),
    ("NAT1", "ISR4331", 200, 150), ("NAT2", "ISR4331", 200, 450),
    ("NAT3", "ISR4331", 800, 450),
    ("SW1", "2960-24TT", 100, 150), ("SW2", "2960-24TT", 100, 450),
    ("SW3", "2960-24TT", 900, 450), ("SW-Srv", "2960-24TT", 800, 150),
    ("PC1", "PC-PT", 40, 90), ("Laptop1", "Laptop-PT", 40, 210),
    ("PC2", "PC-PT", 40, 390), ("Laptop2", "Laptop-PT", 40, 510),
    ("PC3", "PC-PT", 960, 390), ("Laptop3", "Laptop-PT", 960, 510),
    ("Server-Web", "Server-PT", 900, 90),
    ("Server-DNS", "Server-PT", 900, 150), ("PC-Legacy", "PC-PT", 900, 210),
]
LINKS = []
for n in (1, 2, 3):
    LINKS.extend([
        (f"NAT{n}", "GigabitEthernet0/0/0", f"SW{n}", "FastEthernet0/1"),
        (f"SW{n}", "FastEthernet0/2", f"PC{n}", "FastEthernet0"),
        (f"SW{n}", "FastEthernet0/3", f"Laptop{n}", "FastEthernet0"),
    ])
LINKS.extend((f"NAT{n}", "GigabitEthernet0/0/1", f"C{n}", "GigabitEthernet0/0") for n in (1, 2, 3))
LINKS.extend([
    ("C1", "GigabitEthernet0/1", "C2", "GigabitEthernet0/1"),
    ("C2", "GigabitEthernet0/2", "C3", "GigabitEthernet0/1"),
    ("C3", "GigabitEthernet0/2", "C4", "GigabitEthernet0/0"),
    ("C4", "GigabitEthernet0/1", "C1", "GigabitEthernet0/2"),
    ("C4", "GigabitEthernet0/2", "SW-Srv", "FastEthernet0/1"),
    ("SW-Srv", "FastEthernet0/2", "Server-Web", "FastEthernet0"),
    ("SW-Srv", "FastEthernet0/3", "Server-DNS", "FastEthernet0"),
    ("SW-Srv", "FastEthernet0/4", "PC-Legacy", "FastEthernet0"),
])
ROUTERS = ("NAT1", "NAT2", "NAT3", "C1", "C2", "C3", "C4")
IPV4_HOSTS = {
    "Server-Web": ("192.0.2.10", "255.255.255.0", "192.0.2.1"),
    "Server-DNS": ("192.0.2.53", "255.255.255.0", "192.0.2.1"),
    "PC-Legacy": ("192.0.2.20", "255.255.255.0", "192.0.2.1"),
}
SERVICE_TAGS = {
    "HTTP_SERVER", "HTTPS_SERVER", "DNS_SERVER", "DHCP_SERVERS",
    "DHCPV6_SERVER_LIST", "TFTP_SERVER", "FTP_SERVER", "NTP_SERVER",
    "SYSLOG_SERVER", "ACS_SERVER", "EMAIL_SERVER",
}


def set_text(parent, tag, value):
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    el.text = value
    return el


def port_inventory(device, template):
    """Map attested factory interface names to this exact instance's NICs.

    PORT elements have no NAME field. Network names come from the untouched
    template's factory interface declarations, matched by media and order.
    Host names use the skill's convention tier, gated on the installed module.
    No name is derived from the configuration we are about to author.
    """
    actual = [p for p in device.iter("PORT") if p.findtext("TYPE", "").startswith("eCopper")]
    factory = [p for p in template.iter("PORT") if p.findtext("TYPE", "").startswith("eCopper")]
    if [p.findtext("TYPE") for p in actual] != [p.findtext("TYPE") for p in factory]:
        raise ValueError("Instance physical port inventory differs from template")
    model = template.find("ENGINE/TYPE").get("model")
    names = []
    for line in template.findall("ENGINE/RUNNINGCONFIG/LINE"):
        match = re.fullmatch(r"interface ((?:Fast|Gigabit)Ethernet[0-9/]+)", (line.text or "").strip())
        if match:
            names.append(match[1])
    if names:
        if len(names) != len(actual) or len(set(names)) != len(names):
            raise ValueError(f"{model}: factory interface/physical port mismatch")
        for name, p in zip(names, actual):
            media = "eCopperGigabitEthernet" if name.startswith("Gigabit") else "eCopperFastEthernet"
            if p.findtext("TYPE") != media:
                raise ValueError(f"{model}: incompatible media for {name}")
        tier = "template-factory"
    else:
        modules = {m.findtext("MODEL") for m in device.iter("MODULE")}
        expected = "PT-LAPTOP-NM-1CFE" if model == "Laptop-PT" else "PT-HOST-NM-1CFE"
        if model not in {"PC-PT", "Laptop-PT", "Server-PT"} or expected not in modules:
            raise ValueError(f"{model}: no attested port-name rule for installed module")
        if len(actual) != 1 or actual[0].findtext("TYPE") != "eCopperFastEthernet":
            raise ValueError(f"{model}: expected exactly one FastEthernet NIC")
        names, tier = ["FastEthernet0"], "convention+installed-module+user-confirmed"
    return dict(zip(names, actual)), tier


def running_config(name, no_tunnels=False):
    """Convert paste-ready EXEC commands to show-running-config style lines."""
    raw = (HERE / "configs" / f"{name}.txt").read_text(encoding="utf-8").splitlines()
    if raw[:2] != ["enable", "configure terminal"] or raw[-2:] != ["end", "write memory"]:
        raise ValueError(f"{name}: invalid paste-ready CLI wrappers")
    if any(line != line.lstrip() for line in raw):
        raise ValueError(f"{name}: source config must have no leading indentation")
    out, scoped, tunnel = [], False, False
    for line in raw[2:-2]:
        if "OPTIONAL TUNNEL SECTION BEGIN" in line:
            tunnel = True
        if not (no_tunnels and tunnel):
            if line == "exit":
                out.append("!")
                scoped = False
            elif line.startswith("!") or not line:
                out.append(line or "!")
            elif line.startswith(("interface ", "router ", "ipv6 access-list ")):
                out.append(line)
                scoped = True
            else:
                out.append((" " if scoped else "") + line)
        if "OPTIONAL TUNNEL SECTION END" in line:
            tunnel = False
    out.append("end")
    if any(re.search(r"\bnat64\b|\bpassword\b|^enable secret", s, re.I) for s in out):
        raise ValueError(f"{name}: prohibited command")
    return out


def switch_config(name):
    lines = [f"hostname {name}"]
    ports = [ap if a == name else bp for a, ap, b, bp in LINKS if name in (a, b)]
    for port in ports:
        lines += [f"interface {port}", " switchport mode access", " switchport access vlan 1", " no shutdown", "!"]
    return lines + ["end"]


def clean_device(device, name, config):
    eng = device.find("ENGINE")
    sanitize_engine(eng)  # device/engine, NOT the document root (skill warning)
    set_text(eng, "SYS_NAME", name)
    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
        for old in list(eng.findall(tag)):
            eng.remove(old)
        if config is not None:
            block = ET.SubElement(eng, tag)
            for line in config:
                ET.SubElement(block, "LINE").text = line
    # Keep empty service shells so the GUI can enable them manually, but disable
    # all inherited services and clear credentials, including services not audited.
    for block in list(eng):
        if block.tag in SERVICE_TAGS:
            for e in block.iter():
                if e.tag in {"ENABLED", "HTTPSENABLED", "SMTP_ENABLED", "POP3_ENABLED", "ENABLED_SERVER_AUTHENTICATE"}:
                    e.text = "0"
                elif "PASSWORD" in e.tag or e.tag == "USERNAME":
                    e.text = ""
    for tag in ("GATEWAY", "GATEWAYV6", "ISATAP_ROUTER"):
        for e in eng.findall(tag):
            e.text = ""
    for dns in eng.findall("DNS_CLIENT"):
        for e in dns:
            e.text = ""
    for p in device.iter("PORT"):
        if not p.findtext("TYPE", "").startswith("eCopper"):
            continue
        for tag in ("IP", "SUBNET", "PORT_GATEWAY", "PORT_DNS", "IPV6_PORT_GATEWAY", "IPV6_PORT_DNS", "IPV6_LINK_LOCAL", "DESCRIPTION", "IP_UNNUMBERED"):
            if p.find(tag) is not None:
                set_text(p, tag, "")
        for tag in ("PORT_DHCP_ENABLE", "IPV6_ENABLED", "IPV6_ADDRESS_AUTOCONFIG", "IPV6_PORT_AUTO_CONFIG_ENABLED", "IPV6_PORT_DHCP_ENABLED"):
            set_text(p, tag, "false")
        addresses = p.find("IPV6_ADDRESSES")
        if addresses is not None:
            addresses.clear()
        # Regenerate link-local identity from the newly allocated MAC, not donor.
        mac = bytes.fromhex(p.findtext("MACADDRESS").replace(".", ""))
        eui = bytes([mac[0] ^ 2]) + mac[1:3] + b"\xff\xfe" + mac[3:]
        groups = [eui[i:i+2].hex() for i in range(0, 8, 2)]
        set_text(p, "IPV6_DEFAULT_LINK_LOCAL", "FE80::" + ":".join(groups))
    # pc_ip is applied by add_device; restore exactly those authored settings
    # after the blanket sanitisation (all other hosts remain blank).
    if name in IPV4_HOSTS:
        p = next(p for p in device.iter("PORT") if p.findtext("TYPE") == "eCopperFastEthernet")
        ip, mask, gateway = IPV4_HOSTS[name]
        for tag, value in (("IP", ip), ("SUBNET", mask), ("PORT_GATEWAY", gateway)):
            set_text(p, tag, value)
        set_text(eng, "GATEWAY", gateway)


def build(output, no_tunnels=False, stage="full"):
    models, _ = load_templates()
    missing = sorted({model for _, model, _, _ in DEVICES} - models.keys())
    if missing:
        raise ValueError(f"Required template models missing; no substitution allowed: {missing}")
    templates = {model: ET.fromstring(models[model]) for _, model, _, _ in DEVICES}
    lab = Lab()
    lab.prune_seed_devices()
    ids, inventories = {}, {}
    for name, model, x, y in DEVICES:
        config = None
        if stage == "full":
            config = running_config(name, no_tunnels) if name in ROUTERS else switch_config(name) if model == "2960-24TT" else None
        ids[name] = lab.add_device(model, name, x, y, ios_config=config, pc_ip=IPV4_HOSTS.get(name))
        device = lab.devs.findall("DEVICE")[-1]
        inventories[name], tier = port_inventory(device, templates[model])
        print(f"model/ports: {name} {model}: {len(inventories[name])} copper ports ({tier})")
        clean_device(device, name, config)
    used = set()
    # Validate all requested endpoints even for devices-only diagnostic builds.
    for a, ap, b, bp in LINKS:
        for name, port in ((a, ap), (b, bp)):
            if port not in inventories[name]:
                raise ValueError(f"{name}: port {port} does not exist on this exact instance")
            if (name, port) in used:
                raise ValueError(f"Port used twice: {name}:{port}")
            used.add((name, port))
            set_text(inventories[name][port], "POWER", "true")
        if stage != "devices":
            lab.link(ids[a], ap, ids[b], bp)
            # 0.4.1 only emits straight-through copper: adjust the API-created
            # cable's type for two router endpoints; no custom container handling.
            if a in ROUTERS and b in ROUTERS:
                cable = lab.net.find("LINKS").findall("LINK")[-1].find("CABLE")
                set_text(cable, "TYPE", "eCrossOver")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    lab.save(output)
    print(f"Saved {output}: {len(ids)} distinct devices, {0 if stage == 'devices' else len(LINKS)} distinct links; stage={stage}; tunnels={stage == 'full' and not no_tunnels}")
    print("Not opened or tested in Packet Tracer. Run verify_lab.py next.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--no-tunnels", action="store_true")
    parser.add_argument("--stage", choices=("devices", "links", "full"), default="full", help="Compatibility bisection: devices only, then cables, then IOS")
    args = parser.parse_args()
    build(args.output, args.no_tunnels, args.stage)


if __name__ == "__main__":
    main()
