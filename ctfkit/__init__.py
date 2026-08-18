"""ctfkit — modular CTF toolkit for every category.

Structure:
  ctfkit.registry   - tool registry (@tool decorator per module)
  ctfkit.logging    - LogBus + logger setup (streams to console & web UI)
  ctfkit.utils      - shared helpers (hex, scoring, magic bytes, dumps)
  ctfkit.modules.*  - tool implementations per CTF category
"""

__version__ = "1.0.0"
