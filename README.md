# LoanDesk

Working MVP for a mobile loan-request flow, secure server-side OTP verification, encrypted identity/account submission, administrator review, CSV audit export, and API integration.

Start with `README-UR.txt` for the Urdu setup guide and `docs/API.md` for endpoint details.

- Customer app: `/app`
- Administrator portal: `/admin`
- Health: `/api/v1/health`
- OpenAPI / Swagger UI: `/docs`

**Security boundary:** the admin portal can review whether a submitted OTP was correct or incorrect, but the system never stores or displays the raw OTP that a customer typed, and the admin cannot set one shared login OTP for every customer. OTPs are generated server-side, short-lived, single-use, and attempt-limited.

**Deployment boundary:** real SMS delivery, public HTTPS hosting, and provider-backed facial liveness verification require deployment credentials/configuration and are not silently simulated. The local console SMS adapter is development-only.
"# LoanDesk" 
