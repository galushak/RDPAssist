"""Bounded DNS and TCP checks used by diagnostics and Kerberos operations."""

from __future__ import annotations

import socket
import ipaddress
import os
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class TcpCheck:
    host: str
    port: int
    reachable: bool
    detail: str = ""


def check_tcp(host: str, port: int, timeout: float = 3.0) -> TcpCheck:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return TcpCheck(host, port, True)
    except OSError as error:
        return TcpCheck(host, port, False, str(error))


@dataclass(frozen=True)
class ResolvedTarget:
    """The entered target, its SPN-safe hostname, and its transport address."""

    entered_name: str
    hostname: str
    address: str
    dns_domain: str | None = None


@dataclass(frozen=True)
class KdcCandidate:
    """A DNS-discovered Kerberos TCP endpoint and its bounded reachability result."""

    realm: str
    hostname: str
    address: str
    port: int
    priority: int
    weight: int
    source: str
    reachable: bool = True
    detail: str = ""


@dataclass(frozen=True)
class KdcDiscovery:
    realm: str
    candidates: tuple[KdcCandidate, ...]
    selected: KdcCandidate | None = None
    error: str | None = None


DNS_RETRY_DELAY_SECONDS = 0.35
DNS_ATTEMPTS = 3
KDC_DNS_LIFETIME_SECONDS = 3.0
KDC_TCP_TIMEOUT_SECONDS = 2.0


def dns_domain_for_realm(realm: str, configured_domain: str | None = None) -> str | None:
    """Map a DNS-style Kerberos realm to its domain without site-specific values."""
    candidate = (configured_domain or os.environ.get("REMOTE_CONTROL_DNS_DOMAIN") or realm).strip().strip(".")
    if not candidate or "." not in candidate:
        return None
    return candidate.lower()


def _get_addresses(hostname: str) -> list[tuple]:
    return socket.getaddrinfo(
        hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_CANONNAME
    )


def _resolve_with_retries(hostname: str) -> list[tuple]:
    last_error: socket.gaierror | None = None
    for attempt in range(DNS_ATTEMPTS):
        try:
            addresses = _get_addresses(hostname)
            if addresses:
                return addresses
            last_error = socket.gaierror(f"No addresses returned for {hostname}")
        except socket.gaierror as error:
            last_error = error
            if error.errno != socket.EAI_AGAIN:
                break
        if attempt < DNS_ATTEMPTS - 1:
            time.sleep(DNS_RETRY_DELAY_SECONDS)
    raise last_error or socket.gaierror(f"No addresses returned for {hostname}")


def resolve_target_hostname(target: str, *, realm: str | None = None, dns_domain: str | None = None) -> ResolvedTarget:
    """Resolve a hostname for transport and CIFS SPN selection.

    A single-label computer name is retried as ``name.<realm-derived-domain>``
    only after the resolver has failed the entered name.  This avoids guessing a
    deployment-specific suffix while still working on systems without a DNS
    search list.  Numeric targets are reverse-resolved because a CIFS SPN must
    name the host rather than its IP address.
    """
    entered = target.strip().rstrip(".")
    try:
        ipaddress.ip_address(entered)
    except ValueError:
        is_ip = False
    else:
        is_ip = True
    if is_ip:
        try:
            hostname = socket.gethostbyaddr(entered)[0].rstrip(".")
        except OSError as error:
            raise OSError(f"{entered} has no reverse DNS hostname; Kerberos requires a hostname for the CIFS SPN") from error
        return ResolvedTarget(entered, hostname, entered, dns_domain_for_realm(realm or "", dns_domain))

    attempted = [entered]
    if "." not in entered:
        domain = dns_domain_for_realm(realm or "", dns_domain)
        if domain:
            attempted.append(f"{entered}.{domain}")
    last_error: socket.gaierror | None = None
    for candidate in attempted:
        try:
            addresses = _resolve_with_retries(candidate)
        except socket.gaierror as error:
            last_error = error
            continue
        canonical = str(addresses[0][3] or candidate).rstrip(".")
        # libc commonly leaves AI_CANONNAME blank for an A/AAAA answer.  The
        # fully qualified retry is nevertheless an SPN-safe canonical hostname.
        if "." not in canonical and "." in candidate:
            canonical = candidate
        return ResolvedTarget(entered, canonical, str(addresses[0][4][0]), dns_domain_for_realm(realm or "", dns_domain))
    suffix_detail = f"; also tried {attempted[1]}" if len(attempted) > 1 else ""
    raise socket.gaierror(f"Could not resolve {entered}{suffix_detail}: {last_error}")


def _srv_records(realm: str, query: str) -> list[tuple[int, int, int, str]]:
    import dns.resolver

    records = dns.resolver.resolve(query, "SRV", lifetime=KDC_DNS_LIFETIME_SECONDS)
    return [
        (int(record.priority), int(record.weight), int(record.port), str(record.target).rstrip("."))
        for record in records
    ]


def discover_kdcs(realm: str) -> KdcDiscovery:
    """Discover usable KDCs from AD Kerberos SRV records, never from the realm text."""
    normalized_realm = realm.strip().rstrip(".").upper()
    if not normalized_realm:
        return KdcDiscovery("", (), error="No Kerberos realm was configured.")
    sources = (
        (f"_kerberos._tcp.dc._msdcs.{normalized_realm}", "_kerberos._tcp.dc._msdcs"),
        (f"_kerberos._tcp.{normalized_realm}", "_kerberos._tcp"),
    )
    discovered: dict[tuple[str, int], tuple[int, int, int, str, str]] = {}
    errors: list[str] = []
    for query, source in sources:
        try:
            records = _srv_records(normalized_realm, query)
        except Exception as error:
            errors.append(f"{query}: {error}")
            continue
        for priority, weight, port, hostname in records:
            discovered.setdefault((hostname.casefold(), port), (priority, weight, port, hostname, source))
    candidates: list[KdcCandidate] = []
    # Priority is authoritative.  Within a priority, higher SRV weight is a
    # deterministic preference; an unavailable candidate never prevents trying
    # the remaining candidates.
    for priority, weight, port, hostname, source in sorted(discovered.values(), key=lambda item: (item[0], -item[1], item[3].casefold())):
        try:
            addresses = _resolve_with_retries(hostname)
            address = str(addresses[0][4][0])
        except (socket.gaierror, OSError) as error:
            errors.append(f"{hostname}: DNS failed ({error})")
            continue
        status = check_tcp(address, port, timeout=KDC_TCP_TIMEOUT_SECONDS)
        candidate = KdcCandidate(
            normalized_realm, hostname, address, port, priority, weight, source, status.reachable, status.detail,
        )
        candidates.append(candidate)
        if not candidate.reachable:
            errors.append(f"{hostname}:{port}: TCP unavailable ({status.detail})")
    selected = next((candidate for candidate in candidates if candidate.reachable), None)
    return KdcDiscovery(normalized_realm, tuple(candidates), selected, "; ".join(errors) or None)
