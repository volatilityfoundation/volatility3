"""Custom exceptions for Volatility3 MCP server."""

from __future__ import annotations


class MCPVolatilityError(Exception):
    """Base exception for MCP Volatility3 server errors."""


class MemoryImageError(MCPVolatilityError):
    """Raised when a memory image cannot be loaded."""


class PluginError(MCPVolatilityError):
    """Raised when a plugin fails to execute."""


class SymbolTableError(MCPVolatilityError):
    """Raised when symbol table operations fail."""


class LayerError(MCPVolatilityError):
    """Raised when layer operations fail."""
