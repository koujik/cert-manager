# TODO – Next Development Steps

## Short‑term goals
1. **Add unit tests** for the KMS signing workflow (`kms_client`, `utils`).
2. Implement **validation** for the "vHSM KMSバックエンドを使用する" checkbox (ensure user cannot select both KMS and local simultaneously).
3. Create a **management command** to rotate KMS keys and re‑encrypt stored private keys.
4. Improve the **dashboard UI**: add search/filter for certificates, paginate the table.

## Medium‑term enhancements
5. Integrate **Celery** (or Django‑Q) to run background tasks for:
  - Automatic CRL regeneration after a revocation.
  - Periodic Let's Encrypt certificate renewal.
6. Add **DNS‑01 challenge** support via Cloudflare/Route53 API.
7. Implement **Docker** Compose setup (web, db, KMS daemon) for easy deployment.

## Long‑term roadmap
8. Replace the simple SQLite DB with PostgreSQL for production.
9. Add **RBAC** with fine‑grained permissions (e.g., read‑only users).
10. Provide **API endpoints** (OpenAPI spec) for external systems to request certificates.
11. Explore **client‑side encryption** of private keys before sending to the server.

## Feature requests
12. Run Docker containers for each service (web, db, KMS daemon) via Docker Compose.
13. Generate a KMS dashboard to monitor key usage, status, and rotation.
14. Build a vHSM dashboard for visualizing vHSM health, load, and operation metrics.

