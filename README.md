# Kirathimo Family Investment Group v3

A web app for a family investment group — **not a SACCO**.

## What it manages
- Monthly family contributions
- Pro-rata ownership units
- Live NAV and NAV/unit
- Member statements
- Member loans, repayments and overdue debts
- Monthly contribution arrears
- Investments: listed shares, money-market funds, bonds and other assets
- Financial transaction ledger
- Admin audit log
- CSV transaction export
- Public read-only viewing with protected admin changes

## Run locally
Requires Docker Desktop.

```bash
docker compose up --build
```

Open `http://localhost:3000`.

Default local admin values come from `docker-compose.yml`. **Change them before any internet deployment.**

## Production deployment
Use a managed PostgreSQL database and set:
- `DATABASE_URL`
- `JWT_SECRET` to a long random secret
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`

The frontend can be public, while all write endpoints require an admin JWT.

## Important accounting note
The demo database contains seed data for testing. Replace it with Kirathimo's real records before relying on NAV figures. For production accounting, review the cash-flow treatment of investment purchases/sales and add a liability table if the group has external liabilities.
