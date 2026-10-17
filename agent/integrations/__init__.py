"""Integration modules for external tools (BurpSuite, Playwright, terminals)."""

from .burpsuite import BurpSuiteIntegration
from .terminal import TerminalManager

__all__ = ["BurpSuiteIntegration", "TerminalManager"]
