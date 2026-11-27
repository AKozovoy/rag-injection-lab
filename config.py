"""Settings shared by several modules.

Kept in their own file (with no imports) so that rag.py, detectors.py and the
defenses can all use them without importing each other in a circle.
"""

SECRET_CODE = "NW-7731-ALPHA"  # fake secret that later attacks will try to leak

# Domains the assistant may mention, subdomains included (the real IT guide uses
# helpdesk.northwind.internal). Product decision. Shared by the hardened prompt (#13),
# the link detector, the scanner (#14) and the output filter (#15).
LINK_ALLOWLIST = ("northwind-gadgets.example", "northwind.internal")
