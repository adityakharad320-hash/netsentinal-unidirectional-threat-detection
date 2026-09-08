"""
Controlled Traffic Scenario Generator using Scapy.

Generates 6 distinct, high-fidelity synthetic PCAPs in sandboxed, non-routable
IP ranges for deterministic testing and demonstration:
1. BENIGN: Multi-session DNS + HTTPS TLS web traffic.
2. SYN FLOOD (DDoS): Distributed SYN flood targeting 10.0.0.1:80 from spoofed IPs.
3. PORT SCAN: Vertical reconnaissance scanning across ports on 192.168.1.1.
4. DNS / DGA TUNNEL: Algorithmic high-entropy TXT/A record queries.
5. C2 BEACONING: Periodic interval heartbeats with controlled jitter.
6. DATA EXFILTRATION: Asymmetric heavy outbound TCP payload upload.
"""
import time
import random
import string
import logging
from pathlib import Path
from typing import Dict, List, Optional
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

from app.config import SAMPLES_DIR

logger = logging.getLogger(__name__)

class ControlledTrafficGenerator:
    """Generates synthetic PCAPs with customizable attack parameters for live evaluation."""
    
    @staticmethod
    def generate_benign(
        output_path: Path,
        num_domains: int = 4,
        num_sessions: int = 5,
        base_t: Optional[float] = None
    ) -> Path:
        """Scenario 1: Normal bidirectional DNS and HTTPS web traffic."""
        pkts = []
        base_t = base_t or 1724832000.0
        t = base_t
        
        sample_domains = [
            "google.com", "github.com", "microsoft.com", "wikipedia.org",
            "cloudflare.com", "amazon.in", "gov.in", "ntro.gov.in"
        ]
        domains = sample_domains[:max(1, min(num_domains, len(sample_domains)))]
        
        # 1. DNS Queries & Responses
        for i, d in enumerate(domains):
            sport = 50000 + i
            t += 0.03
            pkts.append(Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=sport, dport=53)/
                        DNS(rd=1, qd=DNSQR(qname=d, qtype="A")))
            pkts[-1].time = t
            
            t += 0.02
            pkts.append(Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=sport)/
                        DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname=d, qtype="A"),
                            an=DNSRR(rrname=d, rdata=f"142.250.190.{40 + i}", ttl=300)))
            pkts[-1].time = t
            
        # 2. HTTPS TLS Handshakes and bidirectional data
        for s in range(max(1, num_sessions)):
            dst_ip = f"142.250.190.{40 + (s % len(domains))}"
            sport = 50004 + s
            t += 0.05
            # Client SYN
            pkts.append(Ether()/IP(src="192.168.1.100", dst=dst_ip)/TCP(sport=sport, dport=443, flags="S", seq=1000 + s*100))
            pkts[-1].time = t
            # Server SYN-ACK
            t += 0.015
            pkts.append(Ether()/IP(src=dst_ip, dst="192.168.1.100")/TCP(sport=443, dport=sport, flags="SA", seq=2000 + s*100, ack=1001 + s*100))
            pkts[-1].time = t
            # Client ACK
            t += 0.005
            pkts.append(Ether()/IP(src="192.168.1.100", dst=dst_ip)/TCP(sport=sport, dport=443, flags="A", seq=1001 + s*100, ack=2001 + s*100))
            pkts[-1].time = t
            
            # TLS ClientHello
            t += 0.01
            sni_payload = (
                b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03" + b"\x00" * 32 + b"\x00"
                b"\x00\x02\x13\x01\x01\x00\x00\x8b\x00\x00\x00\x0f\x00\x0d\x00\x00\n"
                b"google.com"
            )
            pkts.append(Ether()/IP(src="192.168.1.100", dst=dst_ip)/TCP(sport=sport, dport=443, flags="PA", seq=1001 + s*100, ack=2001 + s*100)/Raw(load=sni_payload))
            pkts[-1].time = t
            
            # Server Data & Response
            for i in range(8):
                t += 0.04 + (i * 0.01)
                pkts.append(Ether()/IP(src=dst_ip, dst="192.168.1.100")/TCP(sport=443, dport=sport, flags="PA", seq=2001 + s*100 + (i*900), ack=1001 + s*100 + len(sni_payload))/Raw(load=b"X" * 900))
                pkts[-1].time = t

        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 1 (BENIGN): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_syn_flood(
        output_path: Path,
        count: int = 500,
        spoofed_sources: int = 50,
        target_ip: str = "10.0.0.1",
        target_port: int = 80,
        rate_pps: int = 1000,
        base_t: Optional[float] = None
    ) -> Path:
        """Scenario 2: Distributed Volumetric SYN Flood targeting victim server."""
        pkts = []
        base_t = base_t or 1724832000.0
        dt = 1.0 / max(10, rate_pps)
        num_sources = max(1, min(spoofed_sources, count))
        
        for i in range(count):
            t = base_t + (i * dt)
            src_ip = f"172.16.{(i % 10)}.{((i % num_sources) + 1)}"
            sport = 1024 + (i % 64000)
            pkt = Ether()/IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S", seq=100000 + i)
            pkt.time = t
            pkts.append(pkt)
            
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 2 (SYN FLOOD): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_port_scan(
        output_path: Path,
        ports_count: int = 100,
        scanner_ip: str = "192.168.1.50",
        target_ip: str = "192.168.1.1",
        start_port: int = 1,
        speed_pps: int = 100,
        base_t: Optional[float] = None
    ) -> Path:
        """Scenario 3: Vertical Reconnaissance Port Scan probing ports sequentially."""
        pkts = []
        base_t = base_t or 1724832000.0
        dt = 1.0 / max(10, speed_pps)
        
        for i in range(ports_count):
            t = base_t + (i * dt)
            dport = start_port + i
            sport = 40000 + (i % 5000)
            pkt = Ether()/IP(src=scanner_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags="S", seq=50000 + i)
            pkt.time = t
            pkts.append(pkt)
            
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 3 (PORT SCAN): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_dga_dns_tunnel(
        output_path: Path,
        count: int = 8,
        query_type: str = "TXT",
        resolver_ip: str = "8.8.8.8",
        src_ip: str = "192.168.1.75",
        high_entropy: bool = True,
        base_t: Optional[float] = None
    ) -> Path:
        """Scenario 4: Algorithmic high-entropy TXT/A record DNS tunnelling queries."""
        pkts = []
        base_t = base_t or 1724832000.0
        
        for i in range(count):
            t = base_t + (i * 0.20)
            sport = 50000 + i
            if high_entropy:
                random_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
                domain = f"{random_str}.tunnel.exfil.internal"
            else:
                domain = f"sub-{i}.domain.internal"
            
            pkt = Ether()/IP(src=src_ip, dst=resolver_ip)/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))
            pkt.time = t
            pkts.append(pkt)
            
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 4 (DNS/DGA TUNNEL): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_c2_beaconing(
        output_path: Path,
        count: int = 20,
        interval_sec: float = 1.0,
        jitter: float = 0.02,
        c2_ip: str = "198.51.100.42",
        infected_host: str = "10.0.5.12",
        base_t: Optional[float] = None
    ) -> Path:
        """Scenario 5: Periodic interval C2 heartbeats with controlled jitter."""
        pkts = []
        base_t = base_t or 1724832000.0
        
        for i in range(count):
            t_jitter = random.uniform(-jitter, jitter) if jitter > 0 else 0.0
            t = base_t + (i * interval_sec) + t_jitter
            payload = b"C2_HEARTBEAT_STATUS_OK_ID_" + str(i).encode()
            pkt = Ether()/IP(src=infected_host, dst=c2_ip)/TCP(
                sport=49152, dport=8443, flags="PA", seq=1000 + (i*50), ack=2000
            )/Raw(load=payload)
            pkt.time = t
            pkts.append(pkt)
            
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 5 (C2 BEACONING): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @staticmethod
    def generate_data_exfiltration(
        output_path: Path,
        chunk_count: int = 40,
        chunk_size: int = 1400,
        exfil_ip: str = "203.0.113.50",
        src_ip: str = "192.168.1.105",
        base_t: Optional[float] = None
    ) -> Path:
        """Scenario 6: Asymmetric heavy outbound TCP payload upload to external IP."""
        pkts = []
        base_t = base_t or 1724832000.0
        
        # 1. Handshake
        t = base_t
        pkts.append(Ether()/IP(src=src_ip, dst=exfil_ip)/TCP(sport=54321, dport=443, flags="S", seq=1000))
        pkts[-1].time = t
        t += 0.02
        pkts.append(Ether()/IP(src=exfil_ip, dst=src_ip)/TCP(sport=443, dport=54321, flags="SA", seq=5000, ack=1001))
        pkts[-1].time = t
        t += 0.005
        pkts.append(Ether()/IP(src=src_ip, dst=exfil_ip)/TCP(sport=54321, dport=443, flags="A", seq=1001, ack=5001))
        pkts[-1].time = t
        
        # 2. Outbound heavy data burst
        raw_chunk = b"X" * max(100, min(chunk_size - 24, 1420))
        for i in range(chunk_count):
            t += 0.01
            payload = b"EXFIL_DATA_BLOCK_" + raw_chunk
            pkt = Ether()/IP(src=src_ip, dst=exfil_ip)/TCP(
                sport=54321, dport=443, flags="PA", seq=1001 + (i * chunk_size), ack=5001
            )/Raw(load=payload)
            pkt.time = t
            pkts.append(pkt)
            
            # Occasional small ACK from receiver
            if i % 10 == 0:
                t += 0.002
                ack_pkt = Ether()/IP(src=exfil_ip, dst=src_ip)/TCP(
                    sport=443, dport=54321, flags="A", seq=5001, ack=1001 + ((i+1) * chunk_size)
                )
                ack_pkt.time = t
                pkts.append(ack_pkt)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), pkts)
        logger.info(f"Generated Scenario 6 (DATA EXFILTRATION): {len(pkts)} packets -> {output_path.name}")
        return output_path

    @classmethod
    def generate_all_scenarios(cls, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        out = output_dir or SAMPLES_DIR
        out.mkdir(parents=True, exist_ok=True)
        return {
            "BENIGN": cls.generate_benign(out / "benign_traffic.pcap"),
            "SYN_FLOOD": cls.generate_syn_flood(out / "syn_flood.pcap"),
            "PORT_SCAN": cls.generate_port_scan(out / "port_scan.pcap"),
            "DGA_DNS_TUNNEL": cls.generate_dga_dns_tunnel(out / "dga_dns_tunnel.pcap"),
            "C2_BEACONING": cls.generate_c2_beaconing(out / "c2_beaconing.pcap"),
            "DATA_EXFILTRATION": cls.generate_data_exfiltration(out / "data_exfiltration.pcap")
        }
