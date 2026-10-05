import ipaddress
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


def _split(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "cpm_reader"
    mysql_password: str = ""
    mysql_database: str = "forge"

    token_db_url: str = "sqlite+aiosqlite:///./data/cpm_auth.db"

    admin_enabled: bool = True
    admin_api_keys: str = ""
    admin_allowed_cidrs: str = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    admin_cors_origins: str = ""

    allowed_hosts: str = ""

    global_table_denylist: str = (
        "migrations,password_resets,password_reset_tokens,personal_access_tokens,"
        "sessions,failed_jobs,jobs,job_batches,cache,cache_locks,telescope_*,pma__*"
    )
    global_column_denylist: str = (
        "password,password_*,*_password,remember_token,*_secret,*_token,secret*,api_key,stripe_id,pm_last_four"
    )

    max_rows: int = 500
    default_limit: int = 50
    query_timeout_ms: int = 10_000
    max_response_bytes: int = 1_000_000
    max_cell_chars: int = 2_000
    schema_cache_ttl_seconds: int = 300

    @property
    def admin_keys(self) -> list[str]:
        return _split(self.admin_api_keys)

    @property
    def admin_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(cidr, strict=False) for cidr in _split(self.admin_allowed_cidrs)]

    @property
    def admin_cors_origin_list(self) -> list[str]:
        return _split(self.admin_cors_origins)

    @property
    def allowed_host_list(self) -> list[str]:
        return _split(self.allowed_hosts)

    @property
    def table_denylist(self) -> list[str]:
        return [p.lower() for p in _split(self.global_table_denylist)]

    @property
    def column_denylist(self) -> list[str]:
        return [p.lower() for p in _split(self.global_column_denylist)]


@lru_cache
def get_settings() -> Settings:
    return Settings()
