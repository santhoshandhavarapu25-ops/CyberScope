
import subprocess
import xml.etree.ElementTree as ET
import shutil


def scan_localhost(target="127.0.0.1"):
    """Scan localhost only and return discovered ports and services."""

    if target not in ("127.0.0.1", "localhost"):
        raise ValueError("For this initial version, only localhost is allowed.")

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and verify it with nmap --version."
        )

    result = subprocess.run(
        [
            nmap_path,
            "-sT",
            "-sV",
            "--top-ports", "100",
            "-oX", "-",
            target,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Nmap scan failed.")

    root = ET.fromstring(result.stdout)
    rows = []

    for port in root.findall(".//port"):
        state = port.find("state")
        service = port.find("service")

        rows.append({
            "Port": port.get("portid"),
            "Protocol": port.get("protocol"),
            "State": state.get("state") if state is not None else "unknown",
            "Service": service.get("name") if service is not None else "unknown",
            "Version": (
                " ".join(
                    filter(
                        None,
                        [
                            service.get("product"),
                            service.get("version"),
                        ],
                    )
                )
                if service is not None
                else "unknown"
            ),
        })

    return rows
