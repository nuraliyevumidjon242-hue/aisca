# Backend

The FastAPI application exposes authenticated network scan, TLS audit,
heuristic log-analysis, scan-history, alert, and PDF-report endpoints.

See the [project README](../README.md) for setup instructions, environment
configuration, API overview, and the current MVP limitations.

To create an administrator outside Docker, use the interactive helper:

```sh
python backend/scripts/create_admin.py --username admin
```

The helper prompts for the password without placing it in shell history.
