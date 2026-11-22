# Baseera browser extension (Chrome, Manifest V3) — prototype

Checks the URL of the current tab against a Baseera server and shows the Arabic verdict (English toggle) plus the
Aman reporting channels (call 8002626, SMS 2828).

1. Start the server: `./run.sh` (http://127.0.0.1:8000).
2. Chrome → `chrome://extensions` → enable *Developer mode* → *Load unpacked* → select this `extension/` folder.
3. Click the Baseera icon on any page. Change the server URL under *الإعدادات / Settings* if needed.

Privacy: only the current tab URL is sent, only when you open the popup, only to the server you configured,
with `save_case=false` (no case is stored). Permissions: `activeTab`, `storage`, and host access to the API origin only.
The server allows CORS only from `chrome-extension://` origins (override with `BASEERA_CORS_ORIGINS`).
