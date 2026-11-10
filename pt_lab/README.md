# NAT-PT lab — real `.pkt`, built offline

**Open `NAT64_lab.pkt` in Packet Tracer.** It is a binary container authored with
`pkt_core.builder.Lab`, not JavaScript or renamed text. Despite the requested
filename, the configuration uses **NAT-PT**, not NAT64.

**Not opened or tested in Packet Tracer.** Offline verification passes, but that
does not prove Packet Tracer will open it, apply all IOS commands, or pass traffic.
Host IPv6 addressing and server services still require the manual steps below.

## Build, verify, open

Python 3.10+; run from the parent of `pt_lab/`:

```console
python -m pip install packet-tracer-pkt-format==0.4.1
python pt_lab/build_lab.py
python pt_lab/verify_lab.py --report pt_lab/verification.txt
```

Alternatively install `pt_lab/requirements.txt`. The package was also inspected
and installed editable from the sibling `packet-tracer-pkt-format/` checkout.
The scripts use the installed package and bundled resources, not absolute paths
or an uninstalled helper module. No encryption is implemented in these scripts.

Default output is `pt_lab/NAT64_lab.pkt`, resolved relative to the build script.
An optional positional argument chooses another output:

```console
python pt_lab/build_lab.py pt_lab/custom.pkt
python pt_lab/verify_lab.py pt_lab/custom.pkt
```

In Packet Tracer, **File > Open**, select `NAT64_lab.pkt`, complete the manual
settings, run the tests, then **File > Save As** your final filename (for example
`Surname_NAT64.pkt`). Save after edits and reopen it yourself to check persistence.
The seed declares **Packet Tracer 9.0.1.0858**; older versions may reject it.
An outdated run-time-script prompt may appear for harvested models. Upstream
reports that choosing **No** preserves the loaded network; check your own version.

### Files

- `build_lab.py`: devices, cabling, sanitation, IOS adaptation; supports `--no-tunnels`.
- `configs/{NAT1,NAT2,NAT3,C1,C2,C3,C4}.txt`: single source of router commands,
  paste-ready from the user EXEC prompt; no passwords.
- `verify_lab.py`: reopen, round trip, typed inventory, exact endpoints/ports,
  configs, unpack comparison, service audit, addresses, MACs and physical paths.
- `verification.txt`: real offline command output for the delivered file.
- `gates.txt`: additional upstream link/layout/readability/finaliser checks.
- `verification_variants.txt`: byte-identical rebuild, no-tunnels variant and
  deliberate bad-port rejection checks.

## Topology and offline results

There are **20 devices**: 7 routers, 4 switches, 6 island hosts and 3 IPv4
servers/legacy hosts. There are **20 links**, not the 25 mentioned once in the
instructions: 9 island links + 3 NAT/core links + 4 ring links + 4 server links.
The exact Links table, not the inconsistent total, is used by the verifier.

All requested template keys exist: `2911`, `ISR4331`, `2960-24TT`, `PC-PT`,
`Laptop-PT`, `Server-PT`. No model was substituted. Every endpoint is checked on
its actual instantiated chassis before saving and again after decoding.
Network port names come from the original template's factory interface blocks,
matched by ordered physical media. The templates do not give PORT nodes explicit
names. End-device `FastEthernet0` uses the skill's convention tier plus checking
that a single FastEthernet NIC and `PT-HOST-NM-1CFE` / `PT-LAPTOP-NM-1CFE` module
are actually installed; the user also confirmed those names. This is stronger
than guessing from a model label, but still not a PT load test.

Actual offline results (full output in `verification.txt`):

```text
root tag    : PACKETTRACER5
PASS: root PACKETTRACER5; byte-exact encode(decode(file)) == file
Typed model: 20 devices, 20 links; PT seed version 9.0.1.0858
PASS: all 7 unpacked router configs match paste-ready sources after EXEC/exit/indent/comment normalization
device_names: 20 raw, 20 distinct
end_device_ips: 3 raw, 3 distinct
RESULT: PASSED (0 failures, 0 warnings)
```

The independent link audit reports **20 links, findings: none**. The readability
checker reports **0 cable crossings**. The geometry checker does **not** pass:
the exact requested coordinates produce **11 label-inclusive overlaps**, 2 pairs
under the 80-unit spacing floor, and 2 label boxes clipping the page edge.
Coordinates are in pixels at 100% zoom. All device centres fit on the page;
leftmost hosts at x=40 have labels extending left of it. This is an explicit
exception to the skill's recommended layout spacing so the user's coordinate
table is preserved, not a claim that all gates pass. Move/spread devices manually
if readability is more important than retaining those exact coordinates.
The finaliser dry-run with `--no-repack` also fails the geometry gate; sanitation,
audit and round-trip pass. It does not rewrite the delivered artifact.

The upstream Python suite completed with **480 passed, 73 skipped, 11 deselected**
(`python -m pytest tests/`, 218.53 seconds). An initial 120-second run timed out;
the complete rerun above had no time limit. Optional/environment-dependent tests
were skipped. A second independent build produced byte-identical output; the
`--no-tunnels` variant also passed offline verification. Deliberately changing a
cable endpoint to `GigabitEthernet9/9/9` caused the verifier to reject it as expected.
Corpus-wide IOS attestation and PT acceptance/runtime gates were not run: no
external reference corpus or Packet Tracer execution was used.

Donor IOS running/startup configs are replaced with authored configs, including
four simple named access-switch configs derived from the links. Stale host IPs,
gateways, ISR NIC IPs, IPv6 addresses, service records and enabled services are
cleared. Service shells remain **disabled** for later GUI configuration. Router
physical NIC IPv4 fields are blank in the XML: addresses are in IOS RUNNINGCONFIG
and STARTUPCONFIG, not inherited from the template. Only three hosts receive
`pc_ip=(ip, mask, gateway)`. The API does not accept DNS in that tuple, so DNS is
left blank and can be set manually. Used NICs are powered on explicitly.

## Config adaptation and cable handling

The actual API in 0.4.1 is `Lab()`, `prune_seed_devices()`,
`add_device(model, name, x, y, ios_config=..., pc_ip=...)`,
`link(a_id, a_port, b_id, b_port, kind="copper")`, `save(path)`.
The typed **reader** is a different class: `pkt_core.models.Lab.from_bytes(...)`.

`ios_config` is stored verbatim as RUNNINGCONFIG lines, not executed by the
builder. The script strips `enable`, `configure terminal`, `write memory`,
converts `exit` to `!`, indents interface/router/IPv6-ACL subcommands and appends
`end`. It writes identical STARTUPCONFIG too, preventing donor config on reload.
The seven `.txt` files remain plain, unindented, paste-ready CLI files. Unpack
comparison normalizes these expected differences; exact stored line comparison
also detects unexpected added or missing commands.

There is no auto-cable argument in this API: copper links always start as
`eStraightThrough`. The script uses `link()` then changes only the API-created
cable type to `eCrossOver` for the seven router-to-router connections. All
router/switch and switch/host cables stay straight-through.

## Manual host addressing

On each island host, **Desktop > IP Configuration > IPv6**, select static IPv6
and prefix length **64**. Leave IPv4 empty, with IPv4 DHCP disabled.
The builder clears donor IPv4 settings and can leave them empty; it has no
documented host-IPv6 authoring API, so no IPv6 host settings were guessed.

| Host | IPv6 address | IPv6 gateway |
|---|---|---|
| PC1 | 2001:db8:1::10 | 2001:db8:1::1 |
| Laptop1 | 2001:db8:1::11 | 2001:db8:1::1 |
| PC2 | 2001:db8:2::10 | 2001:db8:2::1 |
| Laptop2 | 2001:db8:2::11 | 2001:db8:2::1 |
| PC3 | 2001:db8:3::10 | 2001:db8:3::1 |
| Laptop3 | 2001:db8:3::11 | 2001:db8:3::1 |

The IPv4 hosts are already assigned these settings; confirm them in the GUI:

| Host | IPv4 address | Mask | Gateway |
|---|---|---|---|
| Server-Web | 192.0.2.10 | 255.255.255.0 | 192.0.2.1 |
| Server-DNS | 192.0.2.53 | 255.255.255.0 | 192.0.2.1 |
| PC-Legacy | 192.0.2.20 | 255.255.255.0 | 192.0.2.1 |

Optionally set their IPv4 DNS to `192.0.2.53`; it is not needed for literal-IP tests.

## Manual server services and labels

All donor services are disabled. On **Server-Web > Services > HTTP**, turn HTTP
**On**, edit `index.html`, and save it, for example:

```html
<html><body><h1>NAT-PT lab: IPv4 web server</h1></body></html>
```

Optional: on **Server-DNS > Services > DNS**, enable DNS and add an **AAAA** record
`www.example.test` -> `2001:db8:64::c000:20a` if the GUI supports it.
This is a manual stand-in, **NOT real DNS64**. DNS-server AAAA support is untested.
An IPv6-only client would also need its IPv6 DNS server set to the translated DNS
address `2001:db8:64::c000:235` (192.0.2.53). IPv6 DNS-client settings and DNS over
NAT-PT are untested. Direct IPv6 literals are the baseline and require no DNS.

Optional: manually draw coloured rectangles and notes labelled **IPv6 island
1/2/3**, **NAT-PT routers**, **IPv4 core**, **IPv4 servers/legacy**. The bundled
builder has no documented drawing/annotation API; none was invented here.

## Tunnels and `--no-tunnels`

Full build: NAT1↔NAT2 Tunnel12 (`2001:db8:12::/64`), NAT1↔NAT3 Tunnel13
(`2001:db8:13::/64`), NAT2↔NAT3 Tunnel23 (`2001:db8:23::/64`). IPv4 endpoint
sources/destinations are the NAT routers' `10.0.N.2` addresses. Tunnel interfaces
have **no `ipv6 nat`**. Each config marks its optional tunnel section explicitly.

To omit all tunnels and their IPv6 routes without editing source configs:

```console
python pt_lab/build_lab.py pt_lab/no_tunnels.pkt --no-tunnels
python pt_lab/verify_lab.py pt_lab/no_tunnels.pkt --no-tunnels
```

Inter-island tests cannot pass without tunnels; NAT-PT server tests remain useful.
The default `tunnel mode ipv6ip` is untested in your PT version. Inspect
`tunnel mode ?` locally if rejected. `tunnel mode gre ip` is an alternative to try
on **both ends** for IPv6 over an IPv4 GRE transport. The requested alternative
`tunnel mode gre ipv6` normally means an **IPv6 outer transport**, so it is not a
drop-in replacement for these IPv4 endpoint addresses and IPv4-only core.
Do not assume either alternative works; update the source configs and rebuild
only after confirming suitable support. No NAT64 command is used as a fallback.

## Packet Tracer test plan — expected, not observed

1. On all routers, `show ip interface brief`: every used physical interface should
   be up/up. NAT LAN ports are IPv4-unassigned by design; unused NAT Gi0/0/2 can
   remain unused. Use `show ipv6 interface brief` on NAT routers for LAN/tunnel
   addresses. On C1–C4, `show ip ospf neighbor` should show two FULL ring neighbors
   after convergence (no NAT-router OSPF neighbors). On C4, `show ip route ospf`
   must list `198.51.100.0/28`, `198.51.100.16/28`, `198.51.100.32/28`, normally O E2.
2. PC-Legacy: `ping 192.0.2.10` should receive replies. Fix this baseline first.
   Allow initial ARP/STP/OSPF convergence time.
3. Each of PC1, PC2, PC3: ping its IPv6 gateway, then
   `ping 2001:db8:64::c000:20a`. Expect replies if the NAT-PT dataplane works.
   Browser: `http://[2001:db8:64::c000:20a]` should show the edited page if PT's
   browser accepts IPv6-literal URLs. This URL requires no DNS.
4. PC1: `ping 2001:db8:2::10` and `ping 2001:db8:3::10` should receive replies
   through Tunnel12/Tunnel13, preserving inner IPv6 rather than translating it.
   If not, ping tunnel peer IPv6 addresses and inspect `show ipv6 route` and
   `show interfaces Tunnel12` / `Tunnel13` where supported.
5. On the NAT router handling server traffic: `show ipv6 nat translations` and
   `show ipv6 nat statistics`. Expect a source mapping from the island host into
   that router's pool and increasing counters. Generate traffic while checking;
   mappings can expire. Pools are NAT1 `.1–.14`, NAT2 `.17–.30`, NAT3 `.33–.46`
   under `198.51.100.0/24`, in separate /28s.
6. First test **PC1 -> PC2**, then on C1:

   ```text
   enable
   configure terminal
   interface GigabitEthernet0/1
   shutdown
   end
   ```

   After OSPF reconvergence, expect recovery via **C1–C4–C3–C2**. Some packets may
   be lost during convergence. PC1 -> Web alone does not demonstrate this failover
   because it may already take C1–C4. Restore with:

   ```text
   enable
   configure terminal
   interface GigabitEthernet0/1
   no shutdown
   end
   write memory
   ```

   Wait for FULL neighbors and save the final `.pkt` with the ring restored.
7. Simulation mode: filter for ICMP/ICMPv6, send PC1's web-server ping, step
   through NAT1. Expected input: IPv6 `2001:db8:1::10` ->
   `2001:db8:64::c000:20a`; expected output: IPv4 source from NAT1's pool ->
   `192.0.2.10`. The reply should translate back. Compare inter-island traffic:
   unchanged inner IPv6 inside an outer IPv4 tunnel packet. If PT does not expose
   a header or simulate translation, record that limitation, not a passed test.

## If Packet Tracer says “not compatible with this version”

**Check port names first** (SKILL.md rule 8): one unresolvable port name can make
PT reject the whole document. Offline template checks cannot prove PT accepts
those names in your version. Also check the seed's 9.0.1.0858 version against yours.

Bisect without overwriting the delivered file:

```console
python pt_lab/build_lab.py pt_lab/probe_devices.pkt --stage devices
python pt_lab/build_lab.py pt_lab/probe_links.pkt --stage links
python pt_lab/build_lab.py pt_lab/probe_full.pkt --stage full
```

Open those in order: models/physical scene first, then cables, then configs.
The first two deliberately contain no IOS running/startup config and are diagnostic
only; `verify_lab.py` expects a full lab, so it will reject these incomplete probes.
If devices-only fails, inspect model/seed version/physical data. If adding links
fails, inspect each name against the exact template instance (not a generic
interface list). If only full fails, try `--no-tunnels`, then narrow down the IOS
sections manually. If models themselves are unsupported, obtain a valid matching
template/seed; do not silently substitute another model or change only VERSION.
You can always recreate the links manually and paste `configs/*.txt` as a fallback.

## Known uncertainties

- Actual API signatures and bundled-model availability **were confirmed** from
  0.4.1 source and exercised offline. API storage of commands is not command
  validation: whether PT applies `ipv6 nat`, `ipv6 access-list`, and tunnel
  commands from RUNNINGCONFIG on load as it would when typed remains unverified.
- The user verified `ipv6 nat ?` with prefix/v4v6/v6v4 on ISR4331, but full
  `ipv6 nat v6v4 pool ... prefix-length 28`, source-list syntax, physical-interface
  NAT activation and actual translation support still need local CLI validation.
- `tunnel mode ipv6ip`, GRE alternatives and NAT-PT/tunnel coexistence are
  untested. The source ACL matches all island traffic, including remote islands;
  tunnel route selection versus translation must be checked in the simulator.
- Host IPv6 has no documented builder setter and remains manual. Raw XML fields
  exist, but their presence alone was not treated as a supported authoring API.
- End-host port naming is module/convention-tier evidence, not a PT acceptance
  test; model templates include factory/module state from different PT releases.
- Packet Tracer 9.0.1.0858 seed versus the user's unknown version; IOS image
  feature coverage; saved commands may be rejected even if the file opens.
- AAAA records, DNS over NAT-PT, IPv6-literal HTTP, NAT show commands and
  Simulation-mode translation detail are version-dependent and untested.
- Layout is intentionally the supplied coordinate table, with the recorded
  geometry warnings; no claim of a clean geometry gate or GUI render is made.
