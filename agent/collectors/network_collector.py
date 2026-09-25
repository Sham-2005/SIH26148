"""
Network Forensic Collector
Collects active network connections, open sockets, and network interface adapters.
"""
import psutil
from typing import List, Dict, Any

def collect_network_connections() -> List[Dict[str, Any]]:
    connections = []
    try:
        net_conns = psutil.net_connections(kind='inet')
        for c in net_conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            connections.append({
                "fd": c.fd,
                "family": str(c.family),
                "type": str(c.type),
                "local_address": laddr,
                "remote_address": raddr,
                "status": c.status,
                "pid": c.pid
            })
    except Exception as e:
        connections.append({"error": str(e)})
    return connections

def collect_network_interfaces() -> List[Dict[str, Any]]:
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface_name, addr_list in addrs.items():
        iface_stat = stats.get(iface_name)
        ip_addresses = []
        mac_address = None

        for addr in addr_list:
            if addr.family == psutil.AF_LINK or getattr(addr, 'family', None) == -1:
                mac_address = addr.address
            else:
                ip_addresses.append({
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })

        interfaces.append({
            "interface": iface_name,
            "mac_address": mac_address,
            "ip_addresses": ip_addresses,
            "is_up": iface_stat.isup if iface_stat else False,
            "speed_mbps": iface_stat.speed if iface_stat else 0
        })
    return interfaces

def collect_network_dns() -> Dict[str, Any]:
    return {
        "status": "active",
        "resolver_info": "System default DNS cache"
    }
