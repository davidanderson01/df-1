#!/usr/bin/env python3
"""Domain forensics utility for checking ownership and expiry/transfer clues."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import whois
except Exception:  # pragma: no cover - optional dependency
    whois = None

import requests

DEFAULT_DOMAIN = "elevatecraft.com"
RDAP_URL = "https://rdap.org/domain/{domain}"
AFTERMARKET_NS_HINTS = (
    "afternic",
    "sedo",
    "dan.com",
    "hugedomains",
    "domainagents",
    "dropcatch",
    "namecheap",
    "godaddy",
)


def normalize_domain(domain: str) -> str:
    value = domain.strip().lower().strip("./ ")
    value = value.replace("https://", "").replace("http://", "")
    value = value.split("/")[0]
    value = value.rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", value):
        raise ValueError(f"Invalid domain: {domain!r}")
    return value


def parse_domain_input(value: str) -> list[str]:
    candidates = [item for item in re.split(r"[\s,;]+", value.strip()) if item]
    if not candidates:
        raise ValueError("Enter at least one domain.")

    domains: list[str] = []
    for candidate in candidates:
        normalized = normalize_domain(candidate)
        if normalized not in domains:
            domains.append(normalized)
    return domains


def parse_rdap_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def print_banner(title: str, color: bool = True) -> None:
    line = "=" * 72
    if color:
        print(f"\n\033[1;36m{line}\033[0m")
        print(f"\033[1;33m{title}\033[0m")
        print(f"\033[1;36m{line}\033[0m\n")
    else:
        print(f"\n{line}")
        print(title)
        print(f"{line}\n")


def fetch_rdap(domain: str) -> dict[str, Any]:
    url = RDAP_URL.format(domain=domain)
    response = requests.get(url, timeout=15)
    if response.status_code != 200:
        raise RuntimeError(f"RDAP lookup failed for {domain}: HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(f"RDAP response was not valid JSON for {domain}") from exc
    return data


def get_events(data: dict[str, Any]) -> list[dict[str, Any]]:
    return data.get("events", []) if isinstance(data, dict) else []


def summarize_events(events: Iterable[dict[str, Any]]) -> list[tuple[str, str | None]]:
    summary: list[tuple[str, str | None]] = []
    for event in events:
        action = str(event.get("eventAction", "")).strip()
        date_value = event.get("eventDate")
        if action:
            summary.append((action, date_value))
    return summary


def build_timeline_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, event in enumerate(get_events(data), start=1):
        action = str(event.get("eventAction", "")).strip()
        date_value = event.get("eventDate")
        dt = parse_rdap_datetime(date_value)
        rows.append(
            {
                "sequence": index,
                "eventAction": action,
                "eventDate": date_value or "",
                "timestamp": dt.isoformat().replace("+00:00", "Z") if dt else "",
                "classification": classify_event(action, date_value),
                "notes": describe_event(action, date_value),
            }
        )
    return rows


def classify_event(action: str, date_value: str | None) -> str:
    normalized = (action or "").lower().strip()
    if not normalized:
        return "unknown"
    if normalized in {"registration", "renewal", "expiration", "transfer", "last changed"}:
        return normalized
    return "other"


def describe_event(action: str, date_value: str | None) -> str:
    action_name = (action or "").strip()
    if not action_name:
        return "No action provided"
    if action_name.lower() == "registration":
        return "Domain was first registered"
    if action_name.lower() == "expiration":
        return "Domain reached expiry / renewability window"
    if action_name.lower() in {"transfer", "transfer at registrar"}:
        return "Registrant or registrar changed ownership"
    if action_name.lower() == "last changed":
        return "DNS or registration was updated"
    return "Other RDAP event"


def export_timeline_csv(rows: list[dict[str, Any]], destination: str) -> str:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["eventAction", "eventDate", "timestamp", "classification", "notes", "sequence"]
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return str(path)


def parse_whois_text(text: str) -> dict[str, Any]:
    lower_text = text.lower()
    registrant_organization = ""
    registrar = ""
    creation_date = ""
    expiration_date = ""
    updated_date = ""
    name_servers: list[str] = []

    patterns = {
        "registrar": [
            r"registrar:\s*(.+)",
            r"registrar\s+whois\s+server:\s*(.+)",
        ],
        "creation_date": [
            r"creation\s+date:\s*(.+)",
            r"created:\s*(.+)",
        ],
        "expiration_date": [
            r"registry\s+expiry\s+date:\s*(.+)",
            r"expiration\s+date:\s*(.+)",
            r"renewal\s+date:\s*(.+)",
        ],
        "updated_date": [
            r"updated\s+date:\s*(.+)",
            r"last\s+updated:\s*(.+)",
        ],
        "registrant_organization": [
            r"registrant\s+organization:\s*(.+)",
            r"org:\s*(.+)",
            r"organization:\s*(.+)",
        ],
    }

    for key, regexes in patterns.items():
        for pattern in regexes:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                value = match.group(1).strip().rstrip('.')
                if key == "registrar":
                    registrar = value or ""
                elif key == "creation_date":
                    creation_date = value
                elif key == "expiration_date":
                    expiration_date = value
                elif key == "updated_date":
                    updated_date = value
                elif key == "registrant_organization":
                    registrant_organization = value or ""
                break

    for match in re.finditer(r"name\s+server:\s*([^\r\n]+)", text, re.IGNORECASE):
        value = match.group(1).strip()
        name_servers.append(value)

    return {
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "registrant_organization": registrant_organization,
        "name_servers": sorted(set(name_servers), key=lambda x: x.upper()),
    }


def fetch_whois(domain: str) -> str | None:
    if whois is None:
        return None
    try:
        record = whois.whois(domain)
        if hasattr(record, "text"):
            return str(record.text)
        if isinstance(record, dict):
            return json.dumps(record, indent=2, ensure_ascii=False)
        return str(record)
    except Exception:
        return None


def extract_email_addresses(text: str) -> list[str]:
    if not text:
        return []
    pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    matches = pattern.findall(text)
    seen: set[str] = set()
    ordered: list[str] = []
    for match in matches:
        if match.lower() not in seen:
            seen.add(match.lower())
            ordered.append(match)
    return ordered


def get_email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower().strip().rstrip(".") if "@" in email else ""


def get_registered_domain(hostname: str) -> str:
    labels = hostname.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower().strip(".")


def count_domain_mentions(text: str) -> dict[str, int]:
    pattern = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![\w-])", re.IGNORECASE)
    counts = Counter(get_registered_domain(match) for match in pattern.findall(text or ""))
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_evidence_bundle(
    domain: str,
    rdap_data: dict[str, Any],
    whois_text: str | None = None,
    scan_started_at: datetime | None = None,
) -> dict[str, Any]:
    scan_time = scan_started_at or datetime.now(timezone.utc)
    timeline_rows = build_timeline_rows(rdap_data)
    verdict = classify_domain_history(rdap_data)
    emails = extract_email_addresses((whois_text or "") + "\n" + json.dumps(rdap_data, ensure_ascii=False))
    indicator_map = build_suspicious_indicator_map(domain, rdap_data, whois_text or "")
    relationship_map = build_relationship_map(domain, rdap_data, whois_text or "")
    email_section = build_email_section(domain, emails)

    bundle = {
        "domain": domain,
        "scan_metadata": {
            "scan_started_at_utc": scan_time.isoformat().replace("+00:00", "Z"),
            "report_created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "timezone": "UTC",
        },
        "summary": verdict.get("summary", "No clear domain ownership signal was found."),
        "verdict": verdict.get("verdict", "inconclusive"),
        "confidence": verdict.get("confidence", 0.0),
        "events": timeline_rows,
        "associated_emails": emails,
        "email_section": email_section,
        "relationship_map": relationship_map,
        "suspicious_indicator_map": indicator_map,
        "rdap_status": rdap_data.get("status", []),
        "nameservers": get_nameserver_hints(rdap_data),
        "registrar": get_registrar_names(rdap_data),
        "whois_text": whois_text or "",
    }
    return bundle


def build_suspicious_indicator_map(domain: str, rdap_data: dict[str, Any], whois_text: str = "") -> dict[str, Any]:
    nameservers = get_nameserver_hints(rdap_data)
    status_codes = [str(item).lower() for item in rdap_data.get("status", [])]
    registrar_names = [str(item).lower() for item in get_registrar_names(rdap_data)]
    emails = extract_email_addresses(whois_text or "")

    indicators: dict[str, Any] = {}

    aftermarket_hits = [ns for ns in nameservers if any(hint in ns.lower() for hint in AFTERMARKET_NS_HINTS)]
    indicators["aftermarket_nameservers"] = {
        "count": len(aftermarket_hits),
        "found": aftermarket_hits,
        "rating": min(len(aftermarket_hits) * 25, 100),
    }

    transfer_protection = any(code in status_codes for code in ["client transfer prohibited", "client update prohibited", "client renew prohibited"])
    indicators["transfer_protection"] = {
        "count": int(transfer_protection),
        "found": ["transfer protection enabled"] if transfer_protection else [],
        "rating": 25 if transfer_protection else 0,
    }

    registrar_market_hints = [name for name in registrar_names if any(hint in name for hint in ["godaddy", "namecheap", "sedo", "afternic", "dan.com", "hugedomains", "epik"]) ]
    indicators["registrar_marketplace_patterns"] = {
        "count": len(registrar_market_hints),
        "found": registrar_market_hints,
        "rating": min(len(registrar_market_hints) * 20, 100),
    }

    email_mismatch_count = sum(1 for email in emails if "@" in email and domain not in email.lower())
    indicators["external_email_patterns"] = {
        "count": email_mismatch_count,
        "found": [email for email in emails if domain not in email.lower()],
        "rating": min(email_mismatch_count * 30, 100),
    }

    total_rating = sum(item["rating"] for item in indicators.values())
    indicators["overall_suspicion_rating"] = {
        "count": sum(item["count"] for item in indicators.values() if isinstance(item, dict) and "count" in item),
        "rating": min(total_rating, 100),
        "summary": "High risk" if total_rating >= 70 else "Medium risk" if total_rating >= 35 else "Low risk",
    }
    return indicators


def build_email_section(domain: str, emails: list[str]) -> dict[str, Any]:
    recipients = sorted({email.strip() for email in emails if email and "@" in email})
    target_domain_emails = [email for email in recipients if get_email_domain(email) == domain.lower()]
    external_emails = [email for email in recipients if get_email_domain(email) != domain.lower()]
    email_records = [
        {
            "email": email,
            "associated_domain": get_email_domain(email),
            "is_target_domain": get_email_domain(email) == domain.lower(),
        }
        for email in recipients
    ]
    domain_counts = dict(Counter(record["associated_domain"] for record in email_records if record["associated_domain"]))
    subject = f"Domain ownership and history review for {domain}"
    body = (
        "I am reviewing this domain's historical ownership, transfer, and registrar activity. "
        "Please confirm whether the attached contact emails and domain records are accurate."
    )
    return {
        "subject": subject,
        "body": body,
        "recipients": recipients,
        "target_domain_emails": target_domain_emails,
        "external_emails": external_emails,
        "disclosure_status": (
            "public target-domain email disclosed"
            if target_domain_emails
            else "no public target-domain email disclosed"
        ),
        "email_records": email_records,
        "domain_counts": domain_counts,
        "mailto": "mailto:" + ",".join(recipients) if recipients else "",
        "email_count": len(recipients),
    }


def build_relationship_map(domain: str, rdap_data: dict[str, Any], whois_text: str = "") -> dict[str, Any]:
    emails = extract_email_addresses(whois_text or "")
    nameservers = get_nameserver_hints(rdap_data)
    registrar_names = get_registrar_names(rdap_data)
    registrant_hits = [item for item in emails if domain not in item.lower()]
    evidence_text = (whois_text or "") + "\n" + json.dumps(rdap_data, ensure_ascii=False)
    domain_mentions = count_domain_mentions(evidence_text)

    return {
        "domain": domain,
        "registrar": registrar_names,
        "nameservers": nameservers,
        "email_cluster": {
            "count": len(emails),
            "addresses": emails,
            "records": [
                {"email": email, "associated_domain": get_email_domain(email)}
                for email in emails
            ],
            "associated_domain_counts": dict(Counter(get_email_domain(email) for email in emails if get_email_domain(email))),
            "external_matches": registrant_hits,
        },
        "domain_visit_counters": {
            "definition": "Observed domain mentions in captured RDAP/WHOIS evidence; not confirmed website visits.",
            "counts": domain_mentions,
        },
        "case_summary": {
            "has_market_registrar": bool(registrar_names),
            "has_aftermarket_nameservers": any(any(hint in ns.lower() for hint in AFTERMARKET_NS_HINTS) for ns in nameservers),
            "external_email_count": len(registrant_hits),
        },
    }


def get_registrar_names(data: dict[str, Any]) -> list[str]:
    registrar_names: list[str] = []
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if not roles:
            continue
        if "registrar" in roles or "registrar" in str(roles):
            registrar_names.append(
                entity.get("handle")
                or entity.get("name")
                or str(entity.get("vcardArray", "Unknown registrar"))
            )
    return registrar_names


def get_nameserver_hints(data: dict[str, Any]) -> list[str]:
    ns_values: list[str] = []
    for ns in data.get("nameservers", []):
        value = ns.get("ldhName") or ns.get("hostName") or str(ns)
        ns_values.append(str(value))
    return ns_values


def classify_domain_history(data: dict[str, Any]) -> dict[str, Any]:
    events = get_events(data)
    status_codes = data.get("status", [])
    registrar_names = get_registrar_names(data)
    nameserver_hints = get_nameserver_hints(data)

    event_dates: dict[str, datetime | None] = {}
    for event in events:
        action = str(event.get("eventAction", "")).lower()
        if action and action not in event_dates:
            event_dates[action] = parse_rdap_datetime(event.get("eventDate"))

    registration = event_dates.get("registration")
    expiration = event_dates.get("expiration")
    transfer = event_dates.get("transfer")
    transfer_at_registrar = event_dates.get("transfer at registrar")

    if transfer_at_registrar and transfer is None:
        transfer = transfer_at_registrar

    reasons: list[str] = []
    verdict = "inconclusive"
    confidence = 0.35

    if not events:
        verdict = "insufficient data"
        confidence = 0.1
        reasons = ["No RDAP events were returned for this domain."]
    elif transfer and registration and expiration and transfer >= registration and transfer < expiration:
        verdict = "likely theft or unauthorized transfer"
        confidence = 0.92
        reasons = [
            "A transfer event occurred while the domain was still active or before the recorded expiry window.",
            "That behavior fits unauthorized transfer or takeover more than a normal lapse.",
        ]
    elif expiration and not transfer:
        verdict = "likely lapse / drop-catch"
        confidence = 0.8
        reasons = [
            "The domain expired without a transfer event being recorded.",
            "This is consistent with non-renewal, followed by a drop or aftermarket capture.",
        ]
    elif transfer and expiration and transfer >= expiration:
        verdict = "likely lapse / drop-catch"
        confidence = 0.85
        reasons = [
            "A transfer happened after expiry, which is consistent with a dropped domain being re-acquired.",
            "This pattern is common when the domain is acquired by an investor or drop-catcher after non-renewal.",
        ]
    elif registration and expiration and not transfer:
        verdict = "likely lapse / drop-catch"
        confidence = 0.74
        reasons = [
            "The domain has a valid registration history but no recorded transfer event.",
            "This usually indicates expiry or non-renewal rather than a malicious transfer.",
        ]

    if status_codes:
        status_lower = [str(item).lower() for item in status_codes]
        if any(item in status_lower for item in ["client transfer prohibited", "client update prohibited", "client renew prohibited"]):
            reasons.append("The domain status indicates registrar protections, which reduces the chance of a stealth takeover.")
            if verdict.startswith("likely theft"):
                confidence = min(confidence + 0.03, 0.99)

    matched_ns = [ns for ns in nameserver_hints if any(h in ns.lower() for h in AFTERMARKET_NS_HINTS)]
    if matched_ns:
        reasons.append("Nameserver patterns suggest a parked or aftermarket hosting setup.")
        confidence = min(confidence + 0.05, 0.99)

    if registrar_names:
        registrar_text = " ".join(registrar_names)
        if any(item.lower() in registrar_text.lower() for item in ["godaddy", "namecheap", "epik", "sedo", "afternic", "hugedomains"]):
            reasons.append("Registrar information is consistent with a normal domain marketplace or investor workflow.")

    summary = (
        f"Verdict: {verdict}. "
        + " ".join(reasons[:2])
        if reasons
        else "No clear domain ownership signal was found."
    )

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "summary": summary,
        "reasons": reasons,
        "registration": registration.isoformat().replace("+00:00", "Z") if registration else None,
        "expiration": expiration.isoformat().replace("+00:00", "Z") if expiration else None,
        "transfer": transfer.isoformat().replace("+00:00", "Z") if transfer else None,
        "status_codes": [str(item) for item in status_codes],
        "nameservers": nameserver_hints,
    }


def print_rdap_summary(data: dict[str, Any]) -> None:
    print_banner("RDAP Domain Lookup")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    print_banner("Key dates and status codes")
    for action, dt in summarize_events(get_events(data)):
        print(f"- {action}: {dt}")

    statuses = data.get("status", [])
    if statuses:
        print("\nStatus codes:")
        for status in statuses:
            print(f"  - {status}")
    else:
        print("\nStatus codes: none reported")

    nameservers = data.get("nameservers", [])
    if nameservers:
        print("\nNameservers:")
        for ns in nameservers:
            print(f"  - {ns.get('ldhName') or ns.get('hostName') or ns}")

    registrar_names = get_registrar_names(data)
    if registrar_names:
        print("\nRegistrar:")
        for item in registrar_names:
            print(f"  - {item}")


def print_whois_summary(domain: str) -> None:
    whois_text = fetch_whois(domain)
    if not whois_text:
        print_banner("WHOIS Scan")
        print("WHOIS lookup unavailable in this environment; the python-whois package is not installed.")
        return

    parsed = parse_whois_text(whois_text)
    print_banner("WHOIS Scan")
    print(f"WHOIS text captured for {domain}")
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
    if parsed.get("registrant_organization"):
        print(f"\nRegistrant organization: {parsed['registrant_organization']}")
    if parsed.get("registrar"):
        print(f"Registrar: {parsed['registrar']}")
    if parsed.get("creation_date"):
        print(f"Creation date: {parsed['creation_date']}")
    if parsed.get("expiration_date"):
        print(f"Expiration date: {parsed['expiration_date']}")
    if parsed.get("updated_date"):
        print(f"Updated date: {parsed['updated_date']}")
    if parsed.get("name_servers"):
        print("Name servers:")
        for ns in parsed["name_servers"]:
            print(f"  - {ns}")


def interpret_events(events: Iterable[dict[str, Any]]) -> dict[str, str | None]:
    created: str | None = None
    expiration: str | None = None
    transfer: str | None = None
    last_changed: str | None = None

    for event in events:
        action = str(event.get("eventAction", "")).lower()
        if not action:
            continue
        date_value = event.get("eventDate")

        if action == "registration":
            created = date_value
        elif action == "expiration":
            expiration = date_value
        elif action in {"transfer", "transfer at registrar"}:
            transfer = date_value
        elif action == "last changed":
            last_changed = date_value

    return {
        "created": created,
        "expiration": expiration,
        "transfer": transfer,
        "last_changed": last_changed,
    }


def print_interpretation(report: dict[str, str | None], domain: str, verdict: dict[str, Any] | None = None) -> None:
    print_banner("Interpretation and risk notes")
    created = report.get("created")
    expiration = report.get("expiration")
    transfer = report.get("transfer")
    last_changed = report.get("last_changed")

    print(f"Domain: {domain}")
    print(f"Created: {created}")
    print(f"Expiration: {expiration}")
    print(f"Transfer: {transfer}")
    print(f"Last changed: {last_changed}")

    if verdict:
        print(f"\nClassification: {verdict.get('verdict', 'inconclusive')}")
        print(f"Confidence: {verdict.get('confidence', 0.0):.2f}")
        print(f"Summary: {verdict.get('summary', '')}")
        if verdict.get("reasons"):
            print("\nReasons:")
            for reason in verdict["reasons"]:
                print(f"- {reason}")

    print("\nRough logic:")
    print("- If you see an expiration date followed by a new registration, the domain likely dropped and was re-registered.")
    print("- If there is no transfer event before expiration, the pattern is usually expired -> drop -> investor capture, not theft.")
    print("- A registrar or nameserver jump happening right around expiry is a common sign of aftermarket acquisition.")
    print("- High aftermarket pricing usually indicates a drop-catcher or investor listing, not a ransom or malicious takeover.")

    if transfer is None and expiration:
        print("\nSignal: no transfer event was recorded. This strongly supports a drop/expiry pattern rather than an unauthorized transfer.")
    elif transfer and expiration:
        print("\nSignal: transfer is present. This may indicate a change of ownership after expiration or a transfer between registrars.")


def export_evidence_bundle(
    domain: str,
    rdap_data: dict[str, Any],
    whois_text: str | None = None,
    csv_destination: str | None = None,
    scan_started_at: datetime | None = None,
) -> tuple[str, str]:
    csv_path = Path(csv_destination) if csv_destination else Path.home() / "Downloads" / "report" / "domain_history.csv"
    json_path = csv_path.with_suffix(".json")
    bundle = build_evidence_bundle(domain, rdap_data, whois_text, scan_started_at)
    export_timeline_csv(build_timeline_rows(rdap_data), str(csv_path))
    with json_path.open("w", encoding="utf-8") as outfile:
        json.dump(bundle, outfile, indent=2, ensure_ascii=False)
    return str(csv_path), str(json_path)


def prompt_for_domains() -> list[str]:
    while True:
        raw_value = input("Enter domain(s) to investigate, separated by commas: ").strip()
        try:
            return parse_domain_input(raw_value)
        except ValueError as exc:
            print(f"Invalid domain input: {exc}")


def destination_for_domain(csv_destination: str | None, domain: str, multiple: bool) -> str | None:
    if csv_destination and not multiple:
        return csv_destination
    report_dir = Path.home() / "Downloads" / "report"
    if csv_destination and multiple:
        requested_path = Path(csv_destination)
        return str(requested_path.with_name(f"{requested_path.stem}_{domain}{requested_path.suffix or '.csv'}"))
    return str(report_dir / f"{domain}_domain_history.csv") if multiple else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a domain for RDAP registration, expiry, and transfer clues.")
    parser.add_argument("domains", nargs="*", help="Optional domain(s) to query; otherwise the terminal prompts for them")
    parser.add_argument("--json", action="store_true", help="Print the raw RDAP JSON and exit")
    parser.add_argument("--csv", help="Write a domain history timeline CSV report to the destination path")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if args.domains:
        try:
            domains = parse_domain_input(" ".join(args.domains))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
    else:
        domains = prompt_for_domains()

    for domain in domains:
        scan_started_at = datetime.now(timezone.utc)
        try:
            rdap_data = fetch_rdap(domain)
        except Exception as exc:
            print(f"Error scanning {domain}: {exc}", file=sys.stderr)
            continue

        if args.json:
            print(json.dumps(rdap_data, indent=2, ensure_ascii=False))
            continue

        verdict = classify_domain_history(rdap_data)
        whois_text = fetch_whois(domain)
        csv_destination = destination_for_domain(args.csv, domain, len(domains) > 1)
        csv_path, json_path = export_evidence_bundle(domain, rdap_data, whois_text, csv_destination, scan_started_at)
        print(f"JSON evidence bundle saved to: {json_path}")
        print(f"CSV timeline saved to: {csv_path}")
        print(f"Scan completed at (UTC): {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}")

        print_banner(f"Domain Forensics: {domain}", color=not args.no_color)
        print_rdap_summary(rdap_data)
        print_whois_summary(domain)
        print_interpretation(interpret_events(get_events(rdap_data)), domain, verdict)
        if whois_text:
            emails = extract_email_addresses(whois_text)
            if emails:
                print("\nAssociated email addresses from WHOIS:")
                for email in emails:
                    print(f"  - {email}")
            email_section = build_email_section(domain, emails)
            if email_section["target_domain_emails"]:
                print(f"\nPublic {domain} email addresses:")
                for email in email_section["target_domain_emails"]:
                    print(f"  - {email}")
            else:
                print(f"\nNo public @{domain} email address was disclosed by the WHOIS data.")
            indicator_map = build_suspicious_indicator_map(domain, rdap_data, whois_text)
            print("\nSuspicious indicator map:")
            for key, value in indicator_map.items():
                if isinstance(value, dict):
                    print(f"  - {key}: count={value.get('count', 0)}, rating={value.get('rating', 0)}")

    print("\nInvestigation complete.")
    return 0 if not args.json or domains else 1


if __name__ == "__main__":
    raise SystemExit(main())
