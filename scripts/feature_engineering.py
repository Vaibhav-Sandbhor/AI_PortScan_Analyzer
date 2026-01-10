import xml.etree.ElementTree as ET
import os

# -------------------------------
# CONFIGURATION
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
XML_FILE = os.path.join(PROJECT_ROOT, "nmap_scans", "scan1.xml")

# Common ports (normal services)
COMMON_PORTS = {21, 22, 25, 53, 80, 110, 443}

# Static CVSS mapping (college-friendly)
CVSS_MAP = {
    "ftp": 9.8,
    "ssh": 6.5,
    "http": 5.0,
    "https": 4.5,
    "msrpc": 7.5,
    "microsoft-ds": 8.0,
    "vmware-auth": 7.8
}

# -------------------------------
# STEP 1: PARSE NMAP XML
# -------------------------------
def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts_data = []

    for host in root.findall("host"):
        host_info = {}

        # IP address
        address = host.find("address")
        host_info["ip"] = address.attrib.get("addr") if address is not None else "Unknown"

        # OS detection
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            host_info["os"] = osmatch.attrib.get("name") if osmatch is not None else "Unknown"
        else:
            host_info["os"] = "Unknown"

        open_ports = []
        services = []

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    port_id = int(port.attrib.get("portid"))
                    open_ports.append(port_id)

                    service = port.find("service")
                    if service is not None:
                        services.append(service.attrib.get("name"))

        host_info["open_ports"] = open_ports
        host_info["services"] = list(set(services))

        hosts_data.append(host_info)

    return hosts_data

# -------------------------------
# STEP 2: FEATURE ENGINEERING
# -------------------------------
def calculate_features(host):
    open_ports = host["open_ports"]
    services = host["services"]
    os_name = host["os"].lower()

    open_ports_count = len(open_ports)
    service_count = len(services)

    # CVSS calculation
    cvss_scores = [CVSS_MAP.get(service, 3.0) for service in services]
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0

    # OS flag (Windows = 1, Others = 0)
    os_flag = 1 if "windows" in os_name.lower() or os_name == "unknown" else 0

    # Uncommon port detection
    uncommon_ports = 0
    for port in open_ports:
        if port not in COMMON_PORTS:
            uncommon_ports = 1
            break

    return {
        "open_ports_count": open_ports_count,
        "service_count": service_count,
        "avg_cvss": avg_cvss,
        "uncommon_ports": uncommon_ports,
        "os_flag": os_flag
    }

# -------------------------------
# MAIN
# -------------------------------
if __name__ == "__main__":
    hosts = parse_nmap(XML_FILE)

    print("\n=== FEATURE ENGINEERING OUTPUT ===\n")
    for host in hosts:
        features = calculate_features(host)
        print(features)
