# Community Checks

This directory holds declarative, read-only checks for informal LAN and IoT
vulnerabilities — bugs in ventilation units, inverters, IP cameras, printers,
smart relays, and other local appliances that often never receive a formal CVE.

## Safety Rules

Every check submitted here must satisfy the engine's guardrails (verified via
`uniblue check validate`):

1. **Read-only only (`safety: read-only`)** — HTTP checks may only use `GET`,
   `HEAD`, or `OPTIONS`. Never send state-changing or reboot payloads.
2. **Preconditions required** — Include cheap matching rules (`ports_any`,
   `oui_contains`, `http_title_regex`, etc.) so the probe only runs against
   devices that actually look like the target hardware.
3. **Target-IP only** — Paths must be relative (e.g., `/api/status`). External
   URLs and callbacks are rejected by the runner.
4. **Redact secrets** — Set `redact_body: true` when probing endpoints that may
   expose credentials or tokens so secrets are never written to logs or alerts.

## Testing a New Check Locally

You can test a check directly against a single device on your LAN without
connecting to UniFi:

```sh
uniblue check validate -dir ./checks/community
uniblue check test -target 192.168.1.42 -dir ./checks/community
```
