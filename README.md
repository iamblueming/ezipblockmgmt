Reads AT (access token) and CIDR (IP block) from .env

Auto-creates/maintains a JSON “DB” file at project root: ipdb.json

Renders one page with a table:

IP (read-only)

VMID (editable)

Note (editable)

Clear button (clears VMID + Note)

Saves immediately when the user finishes editing (on blur and on Enter) using fetch() to the same index.php (no extra pages)
