# BAtu-pdk

Packet Tracer NAT-PT lab: three IPv6 islands over an IPv4 core.

- **Lab file:** [pt_lab/NAT64_lab.pkt](pt_lab/NAT64_lab.pkt)
- **Setup, manual steps and tests:** [pt_lab/README.md](pt_lab/README.md)
- **Assignment:** [instruction.txt](instruction.txt)

Rebuild and verify with Python 3.10+:

```console
python -m pip install -r pt_lab/requirements.txt
python pt_lab/build_lab.py
python pt_lab/verify_lab.py
```

The file was generated and verified offline, not opened or tested in Packet
Tracer. IPv6 host addressing and server services require manual setup. See the
lab guide for compatibility uncertainties and layout warnings.
