# Production deployment checklist

Do not put a public customer loan app on the internet until these items are completed.

## Server and secrets

- Set `APP_ENV=production`.
- Set strong, private values for `APP_SECRET`, `APP_ENCRYPTION_KEY`, and `ADMIN_PASSWORD` outside source control.
- Use a supported server, a reverse proxy, HTTPS/TLS, security headers and automatic security updates.
- Use durable encrypted storage/backup for the database and uploads. Back up the encryption key separately with restricted access; if lost, encrypted documents cannot be recovered.
- Restrict network access to the application, database and admin interface as appropriate. Add admin MFA and centralised alerting.
- Configure `DATABASE_PATH` and `LOANDESK_DATA_DIR` in the environment before starting the app.
- If running multiple API instances, replace local SQLite/in-process assumptions with a managed database and shared rate limit/session infrastructure.

## SMS and sign-in

- Configure an approved SMS vendor and verified sender; never use `SMS_PROVIDER=console` in production.
- Store provider credentials in the host's secret manager or environment, never in Android or JavaScript.
- Verify message routing, resend controls, throttling, expiry, attempt limits and incident alerts with the intended countries/carriers.
- Consider a stronger authentication factor for sensitive account actions.

## Identity, face checks and banking data

- Add an approved liveness/identity-verification SDK/API if automated live-presence verification is required. This code currently accepts a selfie image for authorised manual review and does not claim automated liveness detection.
- Publish a clear privacy notice and lawful-purpose/consent flow; define access roles, data retention, deletion, customer support and breach-response procedures.
- Validate acceptable PAN/identity formats for the target jurisdiction and add document-fraud checks as needed.
- Confirm the legal basis for collecting, viewing, retaining and exporting identity numbers, face images and account details.
- Add admin MFA, least-privilege permissions, key rotation, retention/deletion jobs, audit monitoring and security testing before storing real customer data at scale.

## Lending disclosures and operations

- Define the lender entity, operating jurisdiction and currency before launch.
- Display applicable loan terms, charges, rates, tenure, repayment schedule, lender identity, eligibility conditions, complaint/grievance details and required regulatory disclosures before a customer accepts an offer.
- An administrator marking an application `approved` is only a status update; funds are not transferred by this API.

## Android and web

- Host the backend and `/app` on a stable HTTPS domain.
- Set Android `APP_URL` to `https://your-domain/app`; build the release variant with cleartext HTTP disabled.
- Test on supported Android versions and devices, including screen readers, poor connectivity, upload failures and expired sessions.
- Keep the API docs private or access-controlled if your deployment policy requires that.
