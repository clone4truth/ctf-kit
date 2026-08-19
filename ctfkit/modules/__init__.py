"""Import all modules so the registry fills (side-effect of the @tool decorator)."""

from . import encoding, crypto_classic, crypto_modern, stego, forensics, web, rev_pwn, osint, analyze, browser, external, agent, cve  # noqa: F401
