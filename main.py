#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict, field
from datetime import date, datetime
from typing import Any
from urllib.parse import urlparse

import whois


@dataclass
class WhoisInfo:
    domain: str
    registrar: str = "Unknown"
    whois_server: str = "Unknown"
    creation_date: list[str] = field(default_factory=list)
    expiration_date: list[str] = field(default_factory=list)
    updated_date: list[str] = field(default_factory=list)
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    dnssec: str = "Unknown"
    org: str = "Unknown"
    country: str = "Unknown"
    raw_keys: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None


def print_section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def print_kv(key: str, value: str, indent: int = 2) -> None:
    pad = " " * indent
    print(f"{pad}{key:<20} {value}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced WHOIS Lookup Tool"
    )
    parser.add_argument("domain", nargs="?", help="Target domain or URL")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-r", "--raw", action="store_true", help="Print raw WHOIS dictionary")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    return parser.parse_args()


def clean_domain(user_input: str) -> str:
    value = user_input.strip()

    if not value:
        raise ValueError("Empty input.")

    if not value.startswith(("http://", "https://")):
        value = "http://" + value

    parsed = urlparse(value)
    domain = parsed.netloc or parsed.path
    domain = domain.strip().strip("/").lower()

    if not domain:
        raise ValueError("Invalid domain.")

    if " " in domain:
        raise ValueError("Domain contains spaces.")

    if "@" in domain:
        raise ValueError("Email address is not a valid domain input.")

    if ":" in domain:
        domain = domain.split(":", 1)[0].strip()

    if not domain or "." not in domain:
        raise ValueError("Input does not look like a valid domain.")

    return domain


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_text_list(value: Any, lowercase: bool = False, sort_values: bool = True) -> list[str]:
    items = ensure_list(value)
    result: list[str] = []

    for item in items:
        if item is None:
            continue

        text = str(item).strip()
        if not text:
            continue

        if lowercase:
            text = text.lower()

        result.append(text)

    unique = list(dict.fromkeys(result))
    return sorted(unique) if sort_values else unique


def format_date_value(value: Any) -> list[str]:
    items = ensure_list(value)
    result: list[str] = []

    for item in items:
        if item is None:
            continue

        if isinstance(item, datetime):
            result.append(item.strftime("%Y-%m-%d %H:%M:%S"))
        elif isinstance(item, date):
            result.append(item.strftime("%Y-%m-%d"))
        else:
            text = str(item).strip()
            if text:
                result.append(text)

    return list(dict.fromkeys(result))


def normalize_scalar(value: Any) -> str:
    if value is None:
        return "Unknown"

    if isinstance(value, list):
        for item in value:
            if item is not None and str(item).strip():
                return str(item).strip()
        return "Unknown"

    text = str(value).strip()
    return text if text else "Unknown"


def extract_whois_info(domain: str) -> tuple[WhoisInfo, dict[str, Any] | None]:
    info = WhoisInfo(domain=domain)

    try:
        raw = whois.whois(domain)
    except Exception as e:
        info.error = f"WHOIS lookup failed: {e}"
        return info, None

    raw_dict = dict(raw) if raw else {}
    info.raw_keys = sorted(raw_dict.keys())

    info.registrar = normalize_scalar(raw_dict.get("registrar"))
    info.whois_server = normalize_scalar(raw_dict.get("whois_server"))
    info.creation_date = format_date_value(raw_dict.get("creation_date"))
    info.expiration_date = format_date_value(raw_dict.get("expiration_date"))
    info.updated_date = format_date_value(raw_dict.get("updated_date"))
    info.name_servers = normalize_text_list(raw_dict.get("name_servers"), lowercase=True)
    info.status = normalize_text_list(raw_dict.get("status"), sort_values=False)
    info.emails = normalize_text_list(raw_dict.get("emails"), lowercase=True)
    info.dnssec = normalize_scalar(raw_dict.get("dnssec"))
    info.org = normalize_scalar(raw_dict.get("org"))
    info.country = normalize_scalar(raw_dict.get("country"))

    return info, raw_dict


def print_list_block(title: str, values: list[str]) -> None:
    print_kv(f"{title}:", ", ".join(values) if values else "Unknown")


def print_pretty(info: WhoisInfo) -> None:
    print_section("WHOIS Overview")
    print_kv("Domain:", info.domain)

    if not info.success:
        print_kv("Status:", "Failed")
        print_kv("Reason:", info.error or "Unknown")
        return

    print_kv("Registrar:", info.registrar)
    print_kv("WHOIS Server:", info.whois_server)
    print_kv("Organization:", info.org)
    print_kv("Country:", info.country)
    print_kv("DNSSEC:", info.dnssec)

    print_section("Dates")
    print_list_block("Created", info.creation_date)
    print_list_block("Updated", info.updated_date)
    print_list_block("Expires", info.expiration_date)

    print_section("Infrastructure")
    print_list_block("Name Servers", info.name_servers)

    print_section("Status / Contacts")
    print_list_block("Status", info.status)
    print_list_block("Emails", info.emails)

    print_section("Meta")
    print_kv("Raw Field Count:", str(len(info.raw_keys)))
    print_kv("Available Keys:", ", ".join(info.raw_keys) if info.raw_keys else "Unknown")


def make_json_safe(raw_dict: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}

    for key, value in raw_dict.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, (datetime, date)):
            safe[key] = value.isoformat()
        elif isinstance(value, list):
            converted = []
            for item in value:
                if isinstance(item, (datetime, date)):
                    converted.append(item.isoformat())
                else:
                    converted.append(str(item))
            safe[key] = converted
        else:
            safe[key] = str(value)

    return safe


def main() -> None:
    args = parse_args()

    if not args.no_banner:
        print("╔══════════════════════════════════════╗")
        print("║      Advanced WHOIS Lookup Tool      ║")
        print("╚══════════════════════════════════════╝")

    try:
        raw_input_value = args.domain or input("\nEnter domain or URL: ")
        domain = clean_domain(raw_input_value)
    except ValueError as e:
        print(f"\n[!] Input error: {e}")
        return
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        return

    print(f"\n[~] Looking up WHOIS for: {domain}")

    info, raw_dict = extract_whois_info(domain)

    if args.raw:
        print_section("Raw WHOIS Data")
        if raw_dict is None:
            print(info.error or "Unknown error")
            return
        print(json.dumps(make_json_safe(raw_dict), indent=2, ensure_ascii=False))
        return

    if args.json:
        payload = asdict(info)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_pretty(info)


if __name__ == "__main__":
    main()
