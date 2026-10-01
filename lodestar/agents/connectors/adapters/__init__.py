"""Adapter registry. Register new vendor adapters here (one line)."""
from .base import Adapter, AdapterResult
from .csaf import CsafAdapter
from .entra_identity_protection import EntraIdentityProtectionAdapter
from .file_drop import FileDropAdapter
from .hackerone import HackerOneAdapter
from .mailbox import MailboxAdapter
from .misp import MispAdapter
from .mock import MockAdapter
from .ms_graph_security import MsGraphSecurityAdapter
from .taxii import TaxiiAdapter
from .tenable_vm import TenableVmAdapter
from .webhook_inbox import WebhookInboxAdapter

REGISTRY: dict[str, type[Adapter]] = {
    a.name: a for a in (MockAdapter, FileDropAdapter, WebhookInboxAdapter, MsGraphSecurityAdapter,
                        EntraIdentityProtectionAdapter, TenableVmAdapter,
                        HackerOneAdapter, TaxiiAdapter, MispAdapter, CsafAdapter, MailboxAdapter)
}


def build_adapter(name: str, domain, product: str, settings: dict) -> Adapter:
    if name not in REGISTRY:
        raise ValueError(f"Unknown adapter '{name}'. Available: {sorted(REGISTRY)}")
    return REGISTRY[name](domain, product, settings)


__all__ = ["Adapter", "AdapterResult", "REGISTRY", "build_adapter"]
