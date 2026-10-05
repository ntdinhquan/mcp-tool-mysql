from dataclasses import dataclass

from cpm_server.config import Settings
from cpm_server.data.source import DataSource
from cpm_server.security.policy import AccessPolicy
from cpm_server.store.repo import TokenStore


@dataclass
class Services:
    """Everything the MCP tools and the admin API share."""

    settings: Settings
    store: TokenStore
    data: DataSource
    policy: AccessPolicy
