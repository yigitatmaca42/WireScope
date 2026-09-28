"""A small, deliberately non-exhaustive well-known-ports map.

This is a convenience label for common services, not an authoritative
service-detection engine - actual services can and do run on non-standard
ports. Treat the output as a hint, not a fact.
"""

from __future__ import annotations

# (port, protocol) -> service name. Protocol is upper-case "TCP"/"UDP".
_WELL_KNOWN: dict[tuple[int, str], str] = {
    (20, "TCP"): "FTP-DATA",
    (21, "TCP"): "FTP",
    (22, "TCP"): "SSH",
    (23, "TCP"): "Telnet",
    (25, "TCP"): "SMTP",
    (53, "TCP"): "DNS",
    (53, "UDP"): "DNS",
    (67, "UDP"): "DHCP",
    (68, "UDP"): "DHCP",
    (69, "UDP"): "TFTP",
    (80, "TCP"): "HTTP",
    (110, "TCP"): "POP3",
    (111, "TCP"): "RPCBind",
    (123, "UDP"): "NTP",
    (135, "TCP"): "MSRPC",
    (137, "UDP"): "NetBIOS-NS",
    (138, "UDP"): "NetBIOS-DGM",
    (139, "TCP"): "NetBIOS-SSN",
    (143, "TCP"): "IMAP",
    (161, "UDP"): "SNMP",
    (162, "UDP"): "SNMP-Trap",
    (179, "TCP"): "BGP",
    (389, "TCP"): "LDAP",
    (443, "TCP"): "HTTPS",
    (445, "TCP"): "SMB",
    (465, "TCP"): "SMTPS",
    (514, "UDP"): "Syslog",
    (587, "TCP"): "SMTP-Submission",
    (631, "TCP"): "IPP",
    (636, "TCP"): "LDAPS",
    (853, "TCP"): "DNS-over-TLS",
    (873, "TCP"): "Rsync",
    (993, "TCP"): "IMAPS",
    (995, "TCP"): "POP3S",
    (1433, "TCP"): "MSSQL",
    (1521, "TCP"): "Oracle",
    (1723, "TCP"): "PPTP",
    (2049, "TCP"): "NFS",
    (2181, "TCP"): "ZooKeeper",
    (27017, "TCP"): "MongoDB",
    (3128, "TCP"): "HTTP-Proxy",
    (3306, "TCP"): "MySQL",
    (3389, "TCP"): "RDP",
    (5060, "UDP"): "SIP",
    (5432, "TCP"): "PostgreSQL",
    (5900, "TCP"): "VNC",
    (5985, "TCP"): "WinRM",
    (6379, "TCP"): "Redis",
    (6667, "TCP"): "IRC",
    (8000, "TCP"): "HTTP-Alt",
    (8080, "TCP"): "HTTP-Proxy",
    (8443, "TCP"): "HTTPS-Alt",
    (9200, "TCP"): "Elasticsearch",
}

# Ports commonly used for plaintext protocols that leak credentials/content.
PLAINTEXT_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
}


def lookup_service(port: int, protocol: str) -> str | None:
    return _WELL_KNOWN.get((port, protocol.upper()))
