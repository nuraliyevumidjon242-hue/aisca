# AISCA Frontend

The Next.js dashboard provides sign-in, scan/audit forms, log analysis,
authenticated live alerts, risk summaries, and report downloads.

To run locally:
1. cd frontend
2. npm install
3. npm run dev

Configure the backend URL with `NEXT_PUBLIC_API_URL` if it is not
`http://localhost:8000`. Configure the backend admin account using environment
variables; the dashboard no longer contains a built-in account.

See the [project README](../README.md) for the full setup and limitations.
