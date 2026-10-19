# PowerShell Administration Console

PAC is a local-first, read-only system inventory and audit dashboard. The Vue frontend talks to a FastAPI backend, which runs a fixed catalogue of collectors and stores saved audit snapshots in SQLite.

## Current Status

This is a development preview, not a production-ready administration product. Arbitrary shell execution and automatic remediation are not supported. The current full-audit path requires the backend process itself to have administrator/root privileges. A separate, OS-native approval helper is **not implemented yet**; a browser confirmation cannot elevate the backend. Do not expose the backend to a network or use it as a multi-user service.

## Audit Scope

The current audit baseline collects machine and OS information, local accounts and groups, services, installed software, update state, firewall/security settings, scheduled work, remote-access indicators, and bounded event-log summaries. Collector results are reported individually because the available tools and permissions vary by OS. “No findings” is not proof that the machine is secure, and unavailable or denied data is not a passing check.

## Platform Support

The table describes implemented collector paths, not a certification of every OS release. Native approval helpers and a verified release matrix remain outstanding.

| Platform | Current collection path | Prerequisites and limitations |
| --- | --- | --- |
| Windows | PowerShell 7 script using Windows CIM, local account, firewall, update, scheduled-task, and event-log APIs | `pwsh` must be on `PATH`; run the backend elevated for a full audit. The current script collects up to 1,000 events per selected channel. Windows payload behavior has unit coverage, but this repository does not currently provide Windows CI certification. |
| Linux | Native Python collectors plus fixed commands | Full audit currently requires root. Collection depends on available tools: systemd/journalctl for services and logs; dpkg-query or rpm for software; apt for update candidates; and UFW, firewalld, or nftables for firewall state. Missing tools are reported as unavailable. |
| macOS | Native Python collectors plus launchctl and macOS utilities | Full audit currently requires root. Update inventory is unavailable. Firewall/security results depend on `socketfilterfw`, `spctl`, and `fdesetup`. There is no signed privileged-helper installer or macOS CI certification yet. |
| Other | Unsupported | No audit collector is provided. |

The intended release matrix must name tested Windows editions/releases, Linux distributions/releases and required packages, and macOS releases. Until platform CI and native approval helpers exist, treat Linux/macOS as collector previews rather than a supported privileged release.

## Privacy And Storage

Audit snapshots remain on the local machine until manually deleted; PAC does not expire them automatically. The dashboard shows the local database size and saved-audit count and warns when the database exceeds 250 MiB.

By default, PAC removes network addresses, MAC addresses, event messages, account last-logon values, service executable/account paths, scheduled-task arguments and paths, and pseudonymizes account names in saved snapshots. Existing snapshots are redacted in place when the database upgrades to schema version 2; they are not deleted. PDF exports use the same minimized snapshot. Reports can still contain host identity, software inventory, service and firewall metadata, event coverage, and findings. Treat the database and exported reports as sensitive.

Use the Delete action beside a saved audit to delete that audit and its snapshot. Do not copy or publish the SQLite database or PDF reports without reviewing their contents. Native approval and helper installation are not yet implemented; the current backend privilege requirement is described above.

## Development Setup

Prerequisites:

- Python 3.11 or newer
- Node.js 20.19+ or 22.12+ (Vite 8 requirement)
- PowerShell 7 (`pwsh`) for the approved PowerShell diagnostic and Windows collectors
- Platform tools listed in the support matrix for native inventory

Start the backend from the repository root:

```sh
cd backend
python -m venv ../.venv
../.venv/bin/python -m pip install -e '.[dev]'
../.venv/bin/uvicorn pac.main:app --app-dir src --host 127.0.0.1 --port 8000
```

On Windows, activate the virtual environment with `..\.venv\Scripts\Activate.ps1`, install with `python -m pip install -e ".[dev]"`, and start with `python -m uvicorn pac.main:app --app-dir src --host 127.0.0.1 --port 8000`.

In a second terminal:

```sh
cd frontend
npm ci
npm run dev
```

Vite binds to `127.0.0.1:5173` and proxies `/api` to `http://127.0.0.1:8000`. The backend binds to `127.0.0.1:8000`; keep both on loopback.

## Tests And Build

Run backend tests from `backend`:

```sh
../.venv/bin/python -m pytest
```

Run frontend tests and production build from `frontend`:

```sh
npm run test
npm run build
```

Frontend tests use mocked API responses. Collector tests validate normalized payloads and unavailable/partial outcomes; real platform smoke tests and native-helper tests are still required before release.