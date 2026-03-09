"""RAPTOR Hardware Security Package

Automated hardware interface enumeration using Glasgow Interface Explorer.

Installation note: The 'glasgow' pip package (version 0.0.0) is a placeholder.
Install the real Glasgow software from source:
  https://glasgow-embedded.org/latest/install.html
"""

from packages.hardware.enumerator import HardwareEnumerator

__all__ = ["HardwareEnumerator"]
