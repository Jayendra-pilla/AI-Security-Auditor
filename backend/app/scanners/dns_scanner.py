import socket
import time
import logging
import subprocess
import uuid
from urllib.parse import urlparse
from app.scanners.scanner_utils import datetime_now_utc_str, extract_root_domain, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import confidence_for_dns_finding, calculate_confidence

logger = logging.getLogger(__name__)

def query_dns_nslookup(host: str, query_type: str) -> list:
    """
    Query DNS records using the nslookup system utility.
    Returns parsed records as a list of strings.
    """
    try:
        # Cross-platform nslookup execution
        res = subprocess.run(
            ["nslookup", f"-query={query_type}", host],
            capture_output=True,
            text=True,
            timeout=3.0
        )
        output = res.stdout or ""
        records = []
        for line in output.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            
            # Match rules based on record type
            if query_type.upper() == "TXT":
                if "text =" in line_str:
                    records.append(line_str.split("text =", 1)[1].strip().strip('"'))
                elif "TXT" in line_str and "=" in line_str:
                    records.append(line_str.split("=", 1)[1].strip().strip('"'))
            elif query_type.upper() == "MX":
                if "mail exchanger =" in line_str:
                    records.append(line_str.split("mail exchanger =", 1)[1].strip())
                elif "preference =" in line_str:
                    records.append(line_str)
            elif query_type.upper() == "CAA":
                if "caa =" in line_str or "issue" in line_str:
                    records.append(line_str)
        return records
    except Exception as e:
        logger.debug(f"nslookup failed for {host} type {query_type}: {str(e)}")
        return []

class DNSScanner:
    """
    Scanner to inspect target DNS configuration (A, AAAA, MX, TXT, SPF, DMARC, CAA, Wildcard DNS, Reverse DNS).
    
    Uses proper root domain extraction for SPF/DMARC/CAA/MX checks while keeping
    A/AAAA resolution on the original hostname.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"DNSScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        try:
            if target.startswith(("http://", "https://")):
                host = urlparse(target).hostname or ""
            else:
                host = target.split("/")[0]

            if not host:
                host = target

            # Extract root domain for email/certificate DNS checks
            root_domain = extract_root_domain(target)
            logger.info(f"DNSScanner: hostname={host}, root_domain={root_domain}")

            # 1. Resolve A (IPv4) records — use original hostname
            a_records = []
            try:
                addr_info = socket.getaddrinfo(host, None, socket.AF_INET)
                a_records = sorted(list(set(info[4][0] for info in addr_info)))
            except Exception:
                pass

            # 2. Resolve AAAA (IPv6) records — use original hostname
            aaaa_records = []
            try:
                addr_info = socket.getaddrinfo(host, None, socket.AF_INET6)
                aaaa_records = sorted(list(set(info[4][0] for info in addr_info)))
            except Exception:
                pass

            if a_records:
                findings.append({
                    "title": "DNS IPv4 Address Resolution (A Records)",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"A Records resolved: {', '.join(a_records)}",
                    "http_status": "N/A",
                    "affected_url": host,
                    "scanner_name": "DNSScanner",
                    "detection_method": "DNS Query",
                    "timestamp": datetime_now_utc_str(),
                    "description": f"Host '{host}' resolved to the following IPv4 address(es): {', '.join(a_records)}.",
                    "recommendation": "Maintain standard DNS administration policies."
                })

            if aaaa_records:
                findings.append({
                    "title": "DNS IPv6 Address Resolution (AAAA Records)",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"AAAA Records resolved: {', '.join(aaaa_records)}",
                    "http_status": "N/A",
                    "affected_url": host,
                    "scanner_name": "DNSScanner",
                    "detection_method": "DNS Query",
                    "timestamp": datetime_now_utc_str(),
                    "description": f"Host '{host}' resolved to the following IPv6 address(es): {', '.join(aaaa_records)}.",
                    "recommendation": "Ensure IPv6 routing configurations are audited regularly."
                })

            # 3. Reverse DNS lookup for A records
            for ip in a_records[:3]:  # Limit to first 3 IPs
                try:
                    reverse_name = socket.gethostbyaddr(ip)
                    if reverse_name and reverse_name[0]:
                        findings.append({
                            "title": "Reverse DNS Resolution (PTR Record)",
                            "severity": "Informational",
                            "confidence": "High",
                            "evidence": f"IP {ip} → {reverse_name[0]}",
                            "http_status": "N/A",
                            "affected_url": host,
                            "scanner_name": "DNSScanner",
                            "detection_method": "Reverse DNS Query",
                            "timestamp": datetime_now_utc_str(),
                            "description": f"Reverse DNS lookup for {ip} returned hostname: {reverse_name[0]}.",
                            "recommendation": "Verify PTR records match expected hostname assignments."
                        })
                except Exception:
                    pass

            # 4. MX records — use ROOT DOMAIN
            mx_records = query_dns_nslookup(root_domain, "MX")
            if mx_records:
                findings.append({
                    "title": "DNS Mail Exchange Resolution (MX Records)",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"MX Records for {root_domain}: {mx_records}",
                    "http_status": "N/A",
                    "affected_url": root_domain,
                    "scanner_name": "DNSScanner",
                    "detection_method": "DNS Query",
                    "timestamp": datetime_now_utc_str(),
                    "description": f"Root domain '{root_domain}' has active mail server routing configurations: {', '.join(mx_records)}.",
                    "recommendation": "Verify mail servers are configured securely and require TLS."
                })

            # 5. SPF — check on ROOT DOMAIN if target resolves (Phase 4 requirement)
            spf_found = False
            txt_records = []
            if a_records or aaaa_records:
                txt_records = query_dns_nslookup(root_domain, "TXT")
                for txt in txt_records:
                    if txt.lower().startswith("v=spf1"):
                        spf_found = True
                        conf = calculate_confidence(
                            validation_methods=["DNS Validation", "Content Validation"],
                            evidence_quality="high",
                            evidence_count=1,
                            detection_method="DNS query",
                            verification_method="TXT record validation",
                        )
                        findings.append({
                            "title": "DNS SPF Record Discovered",
                            "severity": "Informational",
                            "confidence": conf["confidence"],
                            **{k: v for k, v in conf.items() if k != "confidence"},
                            "evidence": f"SPF Record on {root_domain}: {txt}",
                            "http_status": "N/A",
                            "affected_url": root_domain,
                            "scanner_name": "DNSScanner",
                            "timestamp": datetime_now_utc_str(),
                            "description": f"Root domain '{root_domain}' SPF email validation policy: '{txt}'.",
                            "recommendation": "Maintain strict SPF parameters (e.g. ending in -all instead of ~all) to prevent spoofing."
                        })

            if not spf_found and (a_records or aaaa_records):
                cvss = get_cvss("missing_spf")
                mitre = get_mitre_mapping("email_spoofing")
                conf = calculate_confidence(
                    validation_methods=["DNS Validation"],
                    evidence_quality="high",
                    evidence_count=0,
                    detection_method="DNS query",
                    verification_method="TXT record validation",
                )
                findings.append({
                    "title": "Missing DNS SPF Record",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    **{k: v for k, v in conf.items() if k != "confidence"},
                    "evidence": f"No TXT record matching v=spf1 was returned for root domain '{root_domain}'.",
                    "http_status": "N/A",
                    "affected_url": root_domain,
                    "scanner_name": "DNSScanner",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-15",
                    "cvss_estimate": str(cvss.get("base_score", "3.1")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://cwe.mitre.org/data/definitions/15.html"],
                    "description": f"Root domain '{root_domain}' does not publish an SPF record. Attackers can forge emails from this domain.",
                    "recommendation": f"Publish a TXT record at '{root_domain}' containing valid SPF configurations (e.g. 'v=spf1 include:_spf.{root_domain} -all')."
                })
                severity = "Low"
                status = "warning"

            # 6. DMARC — check on _dmarc.{ROOT DOMAIN}
            dmarc_host = f"_dmarc.{root_domain}"
            dmarc_found = False
            dmarc_records = []
            if a_records or aaaa_records:
                dmarc_records = query_dns_nslookup(dmarc_host, "TXT")
                for txt in dmarc_records:
                    if "v=dmarc1" in txt.lower():
                        dmarc_found = True
                        conf = calculate_confidence(
                            validation_methods=["DNS Validation", "Content Validation"],
                            evidence_quality="high",
                            evidence_count=1,
                            detection_method="DNS query",
                            verification_method="TXT record validation",
                        )
                        findings.append({
                            "title": "DNS DMARC Record Discovered",
                            "severity": "Informational",
                            "confidence": conf["confidence"],
                            **{k: v for k, v in conf.items() if k != "confidence"},
                            "evidence": f"DMARC Record at {dmarc_host}: {txt}",
                            "http_status": "N/A",
                            "affected_url": root_domain,
                            "scanner_name": "DNSScanner",
                            "timestamp": datetime_now_utc_str(),
                            "description": f"Root domain '{root_domain}' publishes a DMARC policy: '{txt}'.",
                            "recommendation": "Ensure DMARC actions are set to quarantine or reject for optimal security."
                        })

            if not dmarc_found and (a_records or aaaa_records):
                cvss = get_cvss("missing_dmarc")
                mitre = get_mitre_mapping("email_spoofing")
                conf = calculate_confidence(
                    validation_methods=["DNS Validation"],
                    evidence_quality="high",
                    evidence_count=0,
                    detection_method="DNS query",
                    verification_method="TXT record validation",
                )
                findings.append({
                    "title": "Missing DNS DMARC Record",
                    "severity": "Low",
                    "confidence": conf["confidence"],
                    **{k: v for k, v in conf.items() if k != "confidence"},
                    "evidence": f"No TXT records found at {dmarc_host} matching v=DMARC1",
                    "http_status": "N/A",
                    "affected_url": root_domain,
                    "scanner_name": "DNSScanner",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-15",
                    "cvss_estimate": str(cvss.get("base_score", "3.1")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://dmarc.org/"],
                    "description": f"Root domain '{root_domain}' does not have a DMARC record at '{dmarc_host}', increasing exposure to email phishing abuse.",
                    "recommendation": f"Configure a TXT record at '_dmarc.{root_domain}' declaring DMARC parameters (e.g. 'v=DMARC1; p=reject;')."
                })
                severity = "Low"
                status = "warning"

            # 7. CAA records — use ROOT DOMAIN
            caa_records = query_dns_nslookup(root_domain, "CAA")
            if caa_records:
                findings.append({
                    "title": "DNS CAA Policy Discovered",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"CAA Records for {root_domain}: {caa_records}",
                    "http_status": "N/A",
                    "affected_url": root_domain,
                    "scanner_name": "DNSScanner",
                    "detection_method": "DNS Query",
                    "timestamp": datetime_now_utc_str(),
                    "description": f"Root domain '{root_domain}' publishes a Certificate Authority Authorization (CAA) policy: {caa_records}.",
                    "recommendation": "Audit CAA configurations regularly."
                })

            # 8. Wildcard DNS Check — use original host
            wildcard_sub = f"x-{uuid.uuid4().hex[:10]}.{host}"
            is_wildcard = False
            try:
                socket.gethostbyname(wildcard_sub)
                is_wildcard = True
            except Exception:
                pass

            if is_wildcard:
                findings.append({
                    "title": "Wildcard DNS Resolution Enabled",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": f"Subdomain '{wildcard_sub}' successfully resolved in DNS.",
                    "http_status": "N/A",
                    "affected_url": host,
                    "scanner_name": "DNSScanner",
                    "detection_method": "Subdomain Resolution Probe",
                    "timestamp": datetime_now_utc_str(),
                    "description": "The DNS server resolves any non-existent subdomains to a default IP mapping.",
                    "recommendation": "Ensure wildcard mappings are intentional and do not hide orphan subdomain takeover targets."
                })

        except Exception as e:
            logger.error(f"DNSScanner error for target {target}: {str(e)}")
            status = "failed"
            severity = "Low"
            findings.append({
                "title": "DNS Host Resolution Failure",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(e),
                "http_status": "N/A",
                "affected_url": target,
                "scanner_name": "DNSScanner",
                "detection_method": "DNS Lookup",
                "timestamp": datetime_now_utc_str(),
                "description": f"Target host '{target}' could not be resolved. Error: {str(e)}",
                "recommendation": "Verify that domain is registered and check DNS server configurations."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"DNSScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "DNSScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
