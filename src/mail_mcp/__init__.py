"""mail-mcp — privacy-first IMAP/SMTP MCP server.

The public Python API is intentionally small; most users interact with the
project via the ``mail-mcp`` CLI or by registering it as an MCP server in
their AI client. The entries re-exported here are the ones stable enough for
downstream code to import.
"""

from .autoconfig import Discovery, ServerSpec, discover
from .config import AccountModel, Config, ConfigModel
from .config import load as load_config

__version__ = "0.3.3"

__all__ = [
    "AccountModel",
    "Config",
    "ConfigModel",
    "Discovery",
    "ServerSpec",
    "__version__",
    "discover",
    "load_config",
]
