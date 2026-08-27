"""Kerberos-first Active Directory computer discovery through Impacket LDAP."""

from __future__ import annotations

import os
from typing import Any

from session_assist.models import AuthenticationMode, Credentials, DirectoryComputer, DirectoryStatus
from session_assist.services.authentication import kerberos_cache_status
from session_assist.services.network import discover_kdcs


def realm_to_base_dn(realm: str) -> str:
    labels = [label for label in realm.strip(".").split(".") if label]
    if not labels:
        raise ValueError("An Active Directory realm is required to derive a search base.")
    return ",".join(f"DC={label}" for label in labels)


def escape_filter_value(value: str) -> str:
    """Escape an RFC 4515 assertion value; query text is never interpolated raw."""
    replacements = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}
    return "".join(replacements.get(character, character) for character in value)


def computer_filter(query: str) -> str:
    safe = escape_filter_value(query.strip())
    if not safe:
        return "(objectCategory=computer)"
    pattern = f"*{safe}*"
    return f"(&(objectCategory=computer)(|(name={pattern})(dNSHostName={pattern})(description={pattern})))"


def _attribute_text(entry: Any, name: str) -> str:
    try:
        for attribute in entry["attributes"]:
            attribute_name = str(attribute["type"])
            if attribute_name.casefold() != name.casefold():
                continue
            values = attribute["vals"]
            if not values:
                return ""
            value = values[0]
            if hasattr(value, "asOctets"):
                value = value.asOctets()
            if isinstance(value, bytes):
                return value.decode("utf-8", "replace")
            return str(value)
    except (KeyError, TypeError, IndexError):
        return ""
    return ""


class DirectoryService:
    """Read-only AD discovery/search; no LDAP credential is persisted or prompted for."""

    def __init__(self, credentials: Credentials, *, ldap_server: str | None = None, search_base: str | None = None) -> None:
        self.credentials = credentials
        self.ldap_server = ldap_server or os.environ.get("REMOTE_CONTROL_LDAP_SERVER")
        self.search_base = search_base or os.environ.get("REMOTE_CONTROL_LDAP_SEARCH_BASE")

    def _realm(self) -> str | None:
        return self.credentials.domain or (kerberos_cache_status().principal or (None, None))[1]

    def _discover_server(self, realm: str) -> str:
        if self.ldap_server:
            return self.ldap_server
        try:
            import dns.resolver
            records = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{realm}", "SRV", lifetime=3)
            best = sorted(records, key=lambda item: (item.priority, -item.weight, str(item.target)))[0]
            return str(best.target).rstrip(".")
        except Exception:
            # A realm A/AAAA record remains a useful DNS fallback on small domains.
            return realm

    def _connect(self, *, discover_base: bool = True) -> tuple[Any, DirectoryStatus]:
        from impacket.ldap import ldap, ldapasn1

        realm = self._realm()
        if not realm:
            return None, DirectoryStatus(None, None, None, error_message="No Kerberos realm or directory domain is configured.")
        server = self._discover_server(realm)
        provisional_base = self.search_base or realm_to_base_dn(realm)
        kdc_host = self.credentials.kdc_host
        if self.credentials.mode is AuthenticationMode.KERBEROS:
            configured = (kdc_host or "").strip().rstrip(".")
            if not configured or configured.casefold() == realm.casefold():
                discovery = discover_kdcs(realm)
                if discovery.selected is None:
                    return None, DirectoryStatus(
                        realm, server, provisional_base,
                        error_message=f"Kerberos KDC discovery failed for {realm}: {discovery.error or 'no reachable SRV candidate'}",
                    )
                kdc_host = discovery.selected.hostname
        try:
            connection = ldap.LDAPConnection(f"ldap://{server}", baseDN=provisional_base)
            connection.kerberosLogin(
                self.credentials.username, self.credentials.password or "", self.credentials.domain,
                kdcHost=kdc_host, useCache=True,
            )
            base = provisional_base
            if discover_base and not self.search_base:
                root = connection.search(
                    searchBase="", scope=ldapasn1.Scope("baseObject"), searchFilter="(objectClass=*)",
                    attributes=["defaultNamingContext"], sizeLimit=1, timeLimit=4,
                )
                if root:
                    base = _attribute_text(root[0], "defaultNamingContext") or provisional_base
            return connection, DirectoryStatus(realm, server, base, authenticated=True)
        except Exception as error:
            return None, DirectoryStatus(realm, server, provisional_base, error_message=str(error))

    def status(self) -> DirectoryStatus:
        connection, status = self._connect()
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        return status

    def search_computers(self, query: str, *, limit: int = 20) -> tuple[DirectoryStatus, list[DirectoryComputer]]:
        """Search only a short query result set; the caller is expected to debounce requests."""
        if not query.strip():
            return DirectoryStatus(self._realm(), self.ldap_server, self.search_base), []
        connection, status = self._connect()
        if connection is None:
            return status, []
        try:
            from impacket.ldap import ldap
            try:
                rows = connection.search(
                    searchBase=status.search_base, searchFilter=computer_filter(query),
                    attributes=["name", "dNSHostName", "description"], sizeLimit=max(1, min(limit, 50)), timeLimit=5,
                )
            except ldap.LDAPSearchError as error:
                rows = error.getAnswers()
            computers = [
                DirectoryComputer(
                    hostname=_attribute_text(row, "name"), dns_hostname=_attribute_text(row, "dNSHostName"),
                    description=_attribute_text(row, "description"),
                )
                for row in rows
            ]
            computers = [computer for computer in computers if computer.hostname]
            computers.sort(key=lambda computer: computer.hostname.casefold())
            return status, computers[:limit]
        except Exception as error:
            return DirectoryStatus(status.realm, status.server, status.search_base, error_message=str(error)), []
        finally:
            try:
                connection.close()
            except Exception:
                pass

    def test_search(self) -> DirectoryStatus:
        """Perform a bounded AD computer query for diagnostics without exposing records."""
        connection, status = self._connect()
        if connection is None:
            return status
        try:
            from impacket.ldap import ldap
            try:
                connection.search(
                    searchBase=status.search_base, searchFilter="(objectCategory=computer)", attributes=["name"],
                    sizeLimit=1, timeLimit=5,
                )
            except ldap.LDAPSearchError as error:
                if not error.getAnswers():
                    raise
            return status
        except Exception as error:
            return DirectoryStatus(status.realm, status.server, status.search_base, error_message=str(error))
        finally:
            try:
                connection.close()
            except Exception:
                pass
