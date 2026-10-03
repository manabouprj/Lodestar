"""Adapter registry. Register new vendor adapters here (one line)."""
from .base import Adapter, AdapterResult
from .csaf import CsafAdapter
from .elastic import ElasticAdapter
from .entra_identity_protection import EntraIdentityProtectionAdapter
from .file_drop import FileDropAdapter
from .google_secops import GoogleSecOpsAdapter
from .hackerone import HackerOneAdapter
from .http_json import HttpJsonAdapter
from .mailbox import MailboxAdapter
from .mcp_client import McpClientAdapter
from .misp import MispAdapter
from .mock import MockAdapter
from .ms_graph_security import MsGraphSecurityAdapter
from .qradar import QRadarAdapter
from .siem import SentinelQueryAdapter, SplunkSearchAdapter
from .sumologic import SumoLogicAdapter
from .taxii import TaxiiAdapter
from .tenable_vm import TenableVmAdapter
from .webhook_inbox import WebhookInboxAdapter

REGISTRY: dict[str, type[Adapter]] = {
    a.name: a for a in (MockAdapter, FileDropAdapter, WebhookInboxAdapter, MsGraphSecurityAdapter,
                        EntraIdentityProtectionAdapter, TenableVmAdapter,
                        HackerOneAdapter, TaxiiAdapter, MispAdapter, CsafAdapter, MailboxAdapter,
                        SentinelQueryAdapter, SplunkSearchAdapter, QRadarAdapter, ElasticAdapter, SumoLogicAdapter,
                        GoogleSecOpsAdapter, HttpJsonAdapter, McpClientAdapter)
}


def build_adapter(name: str, domain, product: str, settings: dict) -> Adapter:
    if name not in REGISTRY:
        raise ValueError(f"Unknown adapter '{name}'. Available: {sorted(REGISTRY)}")
    return REGISTRY[name](domain, product, settings)


__all__ = ["Adapter", "AdapterResult", "REGISTRY", "build_adapter"]
