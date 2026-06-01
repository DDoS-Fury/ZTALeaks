"""
Offline-pcap test harness.

Strategia: i test fabbricano un .pcap (con scapy), poi invocano `snort -r`
in modalità batch sul pcap usando le rule del servizio target. Snort emette
gli alert in fast-format su stdout; il wrapper li parsa in dict.

Niente sniffing live, niente dipendenza dallo stack docker compose dei
microservizi: i test sono deterministici e isolati.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

RULES_DIR = {
    "snort": "/rules/snort",
    "snort-internal": "/rules/snort-internal",
    "snort-mid": "/rules/snort-mid",
}

# Fast-format alert line: pattern identico al regex del parser.go runtime.
FAST_LINE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.*?)\s+\[\*\*\]"
)


@dataclass
class Alert:
    sid: str
    gid: str
    rev: str
    msg: str
    raw: str

    @classmethod
    def from_line(cls, line: str):
        m = FAST_LINE.search(line)
        if not m:
            return None
        return cls(
            sid=m.group("sid"),
            gid=m.group("gid"),
            rev=m.group("rev"),
            msg=m.group("msg").strip(),
            raw=line.strip(),
        )


def _build_snort_conf(service: str, workdir: Path) -> Path:
    """
    Crea uno snort.conf temporaneo che include tutti i file .rules del
    servizio target.
    """
    rules_dir = Path(RULES_DIR[service])
    rule_files = sorted(rules_dir.glob("*.rules"))
    assert rule_files, f"nessuna rules per {service} in {rules_dir}"

    base_conf = Path("/etc/snort/snort-test.conf").read_text()
    includes = "\n".join(f"include {p}" for p in rule_files)

    conf = workdir / "snort.conf"
    conf.write_text(base_conf + "\n" + includes + "\n")
    return conf


def run_snort(service: str, packets) -> List[Alert]:
    """
    Esegue snort offline su un set di pacchetti scapy e ritorna gli alert.
    `packets` deve essere una PacketList o lista compatibile con wrpcap.
    """
    from scapy.utils import wrpcap

    workdir = Path(tempfile.mkdtemp(prefix=f"snort-{service}-"))
    try:
        pcap_path = workdir / "input.pcap"
        wrpcap(str(pcap_path), packets)

        conf_path = _build_snort_conf(service, workdir)

        proc = subprocess.run(
            ["snort", "-q", "-k", "none", "-c", str(conf_path),
             "-r", str(pcap_path), "-A", "console", "-N"],
            capture_output=True, text=True, timeout=30,
        )
        # `-A console` stampa gli alert su stdout in fast-format.
        # `-N` disabilita il logging binario (non ci serve unified2 qui).
        alerts = []
        for line in proc.stdout.splitlines():
            a = Alert.from_line(line)
            if a:
                alerts.append(a)
        return alerts
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.fixture
def snort_offline():
    return run_snort
