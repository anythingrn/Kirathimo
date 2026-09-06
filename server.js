const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.use(express.json());

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-in-production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

// --------------------------------------------------
// DATABASE INITIALIZATION
// --------------------------------------------------

async function init() {
  // IMPORTANT:
  // members MUST be created before users because users.member_id
  // references members(id).

  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      joined_date DATE DEFAULT CURRENT_DATE,
      active BOOLEAN DEFAULT TRUE,
      expected_monthly NUMERIC(14,2) DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'ADMIN',
      member_id INT REFERENCES members(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS contributions (
      id SERIAL PRIMARY KEY,
      member_id INT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      amount NUMERIC(14,2) NOT NULL,
      units NUMERIC(18,6) DEFAULT 0,
      unit_price NUMERIC(14,6) DEFAULT 1,
      contribution_date DATE DEFAULT CURRENT_DATE,
      month_for DATE,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS loans (
      id SERIAL PRIMARY KEY,
      member_id INT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
      principal NUMERIC(14,2) NOT NULL,
      interest_rate NUMERIC(8,4) DEFAULT 0,
      principal_paid NUMERIC(14,2) DEFAULT 0,
      interest_paid NUMERIC(14,2) DEFAULT 0,
      issued_date DATE DEFAULT CURRENT_DATE,
      due_date DATE,
      status TEXT DEFAULT 'ACTIVE',
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS loan_repayments (
      id SERIAL PRIMARY KEY,
      loan_id INT NOT NULL REFERENCES loans(id) ON DELETE CASCADE,
      amount NUMERIC(14,2) NOT NULL,
      repayment_date DATE DEFAULT CURRENT_DATE,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS investments (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'OTHER',
      units NUMERIC(18,6) DEFAULT 0,
      purchase_price NUMERIC(14,2) DEFAULT 0,
      current_value NUMERIC(14,2) DEFAULT 0,
      purchase_date DATE DEFAULT CURRENT_DATE,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS investment_values (
      id SERIAL PRIMARY KEY,
      investment_id INT NOT NULL REFERENCES investments(id) ON DELETE CASCADE,
      value NUMERIC(14,2) NOT NULL,
      value_date DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      member_id INT REFERENCES members(id) ON DELETE SET NULL,
      transaction_type TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      description TEXT,
      reference_id INT,
      transaction_date DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id INT,
      details TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS nav_snapshots (
      id SERIAL PRIMARY KEY,
      nav NUMERIC(18,2) NOT NULL,
      units NUMERIC(18,6) NOT NULL,
      unit_price NUMERIC(18,8) NOT NULL,
      snapshot_date DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Create a default admin if one does not exist.
  const adminEmail =
    process.env.ADMIN_EMAIL || "admin@kirathimo.local";

  const adminPassword =
    process.env.ADMIN_PASSWORD || "ChangeMe123!";

  const existingAdmin = await pool.query(
    "SELECT id FROM users WHERE email = $1",
    [adminEmail]
  );

  if (existingAdmin.rowCount === 0) {
    const passwordHash = await bcrypt.hash(adminPassword, 12);

    await pool.query(
      `INSERT INTO users(email, password_hash, role)
       VALUES($1, $2, 'ADMIN')`,
      [adminEmail, passwordHash]
    );

    console.log(`Default admin created: ${adminEmail}`);
  }

  console.log("Database initialized successfully.");
}

// --------------------------------------------------
// AUTHENTICATION
// --------------------------------------------------

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      member_id: user.member_id
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "ADMIN") {
    return res.status(403).json({
      error: "Administrator access required"
    });
  }

  next();
}

// --------------------------------------------------
// HEALTH
// --------------------------------------------------

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "Kirathimo Family Investment Group",
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      database: "error"
    });
  }
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash, role, member_id
       FROM users
       WHERE LOWER(email) = LOWER($1)`,
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const token = createToken(user);

    await pool.query(
      `INSERT INTO audit_logs(user_id, action, entity_type, details)
       VALUES($1, 'LOGIN', 'USER', $2)`,
      [user.id, `User ${user.email} logged in`]
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        member_id: user.member_id
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

// --------------------------------------------------
// NAV CALCULATION
// --------------------------------------------------

async function calculateNAV() {
  const contributions = await pool.query(`
    SELECT COALESCE(SUM(amount), 0) AS total
    FROM contributions
  `);

  const loans = await pool.query(`
    SELECT COALESCE(
      SUM(GREATEST(principal - principal_paid, 0)),
      0
    ) AS total
    FROM loans
    WHERE status <> 'WRITTEN_OFF'
  `);

  const investments = await pool.query(`
    SELECT COALESCE(SUM(current_value), 0) AS total
    FROM investments
  `);

  const transactions = await pool.query(`
    SELECT
      COALESCE(
        SUM(
          CASE
            WHEN transaction_type IN (
              'CONTRIBUTION',
              'LOAN_REPAYMENT',
              'OTHER_INCOME'
            )
            THEN amount

            WHEN transaction_type IN (
              'INVESTMENT_PURCHASE',
              'LOAN_ISSUED',
              'OTHER_EXPENSE'
            )
            THEN -amount

            ELSE 0
          END
        ),
        0
      ) AS cash
    FROM transactions
  `);

  const units = await pool.query(`
    SELECT COALESCE(SUM(units), 0) AS total
    FROM contributions
  `);

  const totalContributions =
    Number(contributions.rows[0].total || 0);

  const outstandingLoans =
    Number(loans.rows[0].total || 0);

  const investmentValue =
    Number(investments.rows[0].total || 0);

  const cash =
    Number(transactions.rows[0].cash || 0);

  const totalUnits =
    Number(units.rows[0].total || 0);

  const nav =
    cash +
    investmentValue +
    outstandingLoans;

  const unitPrice =
    totalUnits > 0
      ? nav / totalUnits
      : 1;

  return {
    nav,
    totalUnits,
    unitPrice,
    cash,
    investmentValue,
    outstandingLoans,
    totalContributions
  };
}

app.get("/api/nav", async (req, res) => {
  try {
    const nav = await calculateNAV();

    res.json(nav);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to calculate NAV"
    });
  }
});

// --------------------------------------------------
// DASHBOARD
// --------------------------------------------------

app.get("/api/dashboard", async (req, res) => {
  try {
    const nav = await calculateNAV();

    const members = await pool.query(`
      SELECT COUNT(*) AS count
      FROM members
      WHERE active = TRUE
    `);

    const investments = await pool.query(`
      SELECT COUNT(*) AS count
      FROM investments
    `);

    const loans = await pool.query(`
      SELECT COUNT(*) AS count
      FROM loans
      WHERE status = 'ACTIVE'
    `);

    res.json({
      ...nav,
      activeMembers: Number(members.rows[0].count),
      investments: Number(investments.rows[0].count),
      activeLoans: Number(loans.rows[0].count)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load dashboard"
    });
  }
});

// --------------------------------------------------
// MEMBERS
// --------------------------------------------------

app.get("/api/members", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        m.*,
        COALESCE(c.total_contributed, 0) AS total_contributed,
        COALESCE(c.total_units, 0) AS total_units,
        COALESCE(l.loan_balance, 0) AS loan_balance
      FROM members m

      LEFT JOIN (
        SELECT
          member_id,
          SUM(amount) AS total_contributed,
          SUM(units) AS total_units
        FROM contributions
        GROUP BY member_id
      ) c ON c.member_id = m.id

      LEFT JOIN (
        SELECT
          member_id,
          SUM(GREATEST(principal - principal_paid, 0))
            AS loan_balance
        FROM loans
        WHERE status <> 'WRITTEN_OFF'
        GROUP BY member_id
      ) l ON l.member_id = m.id

      ORDER BY m.name
    `);

    const nav = await calculateNAV();

    const members = result.rows.map(member => {
      const units = Number(member.total_units || 0);

      return {
        ...member,
        total_contributed: Number(member.total_contributed || 0),
        total_units: units,
        loan_balance: Number(member.loan_balance || 0),
        ownership_percent:
          nav.totalUnits > 0
            ? (units / nav.totalUnits) * 100
            : 0,
        ownership_value:
          units * nav.unitPrice
      };
    });

    res.json(members);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load members"
    });
  }
});

app.get("/api/members/:id", async (req, res) => {
  try {
    const memberId = Number(req.params.id);

    const memberResult = await pool.query(
      `SELECT * FROM members WHERE id = $1`,
      [memberId]
    );

    if (memberResult.rowCount === 0) {
      return res.status(404).json({
        error: "Member not found"
      });
    }

    const member = memberResult.rows[0];

    const contributions = await pool.query(
      `SELECT *
       FROM contributions
       WHERE member_id = $1
       ORDER BY contribution_date DESC, id DESC`,
      [memberId]
    );

    const loans = await pool.query(
      `SELECT *
       FROM loans
       WHERE member_id = $1
       ORDER BY issued_date DESC, id DESC`,
      [memberId]
    );

    const transactions = await pool.query(
      `SELECT *
       FROM transactions
       WHERE member_id = $1
       ORDER BY transaction_date DESC, id DESC`,
      [memberId]
    );

    const nav = await calculateNAV();

    const totalContributed =
      contributions.rows.reduce(
        (sum, row) => sum + Number(row.amount || 0),
        0
      );

    const totalUnits =
      contributions.rows.reduce(
        (sum, row) => sum + Number(row.units || 0),
        0
      );

    const loanBalance =
      loans.rows.reduce(
        (sum, row) =>
          sum +
          Math.max(
            Number(row.principal || 0) -
              Number(row.principal_paid || 0),
            0
          ),
        0
      );

    res.json({
      member,
      contributions: contributions.rows,
      loans: loans.rows,
      transactions: transactions.rows,
      summary: {
        totalContributed,
        totalUnits,
        ownershipPercent:
          nav.totalUnits > 0
            ? (totalUnits / nav.totalUnits) * 100
            : 0,
        ownershipValue:
          totalUnits * nav.unitPrice,
        loanBalance
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load member"
    });
  }
});

app.post(
  "/api/members",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        name,
        phone,
        email,
        joined_date,
        expected_monthly
      } = req.body;

      if (!name) {
        return res.status(400).json({
          error: "Name is required"
        });
      }

      const result = await pool.query(
        `INSERT INTO members
          (name, phone, email, joined_date, expected_monthly)
         VALUES($1, $2, $3, COALESCE($4, CURRENT_DATE), $5)
         RETURNING *`,
        [
          name,
          phone || null,
          email || null,
          joined_date || null,
          Number(expected_monthly || 0)
        ]
      );

      const member = result.rows[0];

      await pool.query(
        `INSERT INTO audit_logs
          (user_id, action, entity_type, entity_id, details)
         VALUES($1, 'CREATE', 'MEMBER', $2, $3)`,
        [
          req.user.id,
          member.id,
          `Created member ${member.name}`
        ]
      );

      res.status(201).json(member);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to create member"
      });
    }
  }
);

// --------------------------------------------------
// CONTRIBUTIONS
// --------------------------------------------------

app.get("/api/contributions", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        c.*,
        m.name AS member_name
      FROM contributions c
      JOIN members m ON m.id = c.member_id
      ORDER BY c.contribution_date DESC, c.id DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load contributions"
    });
  }
});

app.post(
  "/api/contributions",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        member_id,
        amount,
        contribution_date,
        month_for,
        notes
      } = req.body;

      if (!member_id || !amount || Number(amount) <= 0) {
        return res.status(400).json({
          error: "Valid member and amount are required"
        });
      }

      const nav = await calculateNAV();

      const unitPrice =
        nav.totalUnits > 0
          ? nav.unitPrice
          : 1;

      const units =
        Number(amount) / unitPrice;

      const contribution = await pool.query(
        `INSERT INTO contributions
          (member_id, amount, units, unit_price,
           contribution_date, month_for, notes)
         VALUES($1, $2, $3, $4,
           COALESCE($5, CURRENT_DATE),
           $6, $7)
         RETURNING *`,
        [
          member_id,
          Number(amount),
          units,
          unitPrice,
          contribution_date || null,
          month_for || null,
          notes || null
        ]
      );

      const contributionId =
        contribution.rows[0].id;

      await pool.query(
        `INSERT INTO transactions
          (member_id, transaction_type, amount,
           description, reference_id, transaction_date)
         VALUES($1, 'CONTRIBUTION', $2, $3, $4,
           COALESCE($5, CURRENT_DATE))`,
        [
          member_id,
          Number(amount),
          "Member contribution",
          contributionId,
          contribution_date || null
        ]
      );

      await pool.query(
        `INSERT INTO audit_logs
          (user_id, action, entity_type, entity_id, details)
         VALUES($1, 'CREATE', 'CONTRIBUTION', $2, $3)`,
        [
          req.user.id,
          contributionId,
          `Recorded contribution of ${amount}`
        ]
      );

      res.status(201).json(contribution.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to record contribution"
      });
    }
  }
);

// --------------------------------------------------
// LOANS
// --------------------------------------------------

app.get("/api/loans", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        l.*,
        m.name AS member_name,
        GREATEST(l.principal - l.principal_paid, 0)
          AS outstanding
      FROM loans l
      JOIN members m ON m.id = l.member_id
      ORDER BY l.issued_date DESC, l.id DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load loans"
    });
  }
});

app.post(
  "/api/loans",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        member_id,
        principal,
        interest_rate,
        issued_date,
        due_date,
        notes
      } = req.body;

      if (!member_id || !principal || Number(principal) <= 0) {
        return res.status(400).json({
          error: "Valid member and principal are required"
        });
      }

      const result = await pool.query(
        `INSERT INTO loans
          (member_id, principal, interest_rate,
           issued_date, due_date, notes)
         VALUES($1, $2, $3,
           COALESCE($4, CURRENT_DATE),
           $5, $6)
         RETURNING *`,
        [
          member_id,
          Number(principal),
          Number(interest_rate || 0),
          issued_date || null,
          due_date || null,
          notes || null
        ]
      );

      const loan = result.rows[0];

      await pool.query(
        `INSERT INTO transactions
          (member_id, transaction_type, amount,
           description, reference_id, transaction_date)
         VALUES($1, 'LOAN_ISSUED', $2, $3, $4,
           COALESCE($5, CURRENT_DATE))`,
        [
          member_id,
          Number(principal),
          "Loan issued",
          loan.id,
          issued_date || null
        ]
      );

      await pool.query(
        `INSERT INTO audit_logs
          (user_id, action, entity_type, entity_id, details)
         VALUES($1, 'CREATE', 'LOAN', $2, $3)`,
        [
          req.user.id,
          loan.id,
          `Issued loan of ${principal}`
        ]
      );

      res.status(201).json(loan);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to create loan"
      });
    }
  }
);

app.post(
  "/api/loans/:id/repay",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const loanId = Number(req.params.id);
      const amount = Number(req.body.amount);

      if (!amount || amount <= 0) {
        return res.status(400).json({
          error: "Valid repayment amount is required"
        });
      }

      const loanResult = await pool.query(
        `SELECT *
         FROM loans
         WHERE id = $1`,
        [loanId]
      );

      if (loanResult.rowCount === 0) {
        return res.status(404).json({
          error: "Loan not found"
        });
      }

      const loan = loanResult.rows[0];

      const outstanding = Math.max(
        Number(loan.principal) -
          Number(loan.principal_paid),
        0
      );

      if (outstanding <= 0) {
        return res.status(400).json({
          error: "This loan is already fully repaid"
        });
      }

      const repayment = Math.min(
        amount,
        outstanding
      );

      const newPrincipalPaid =
        Number(loan.principal_paid) +
        repayment;

      const newStatus =
        newPrincipalPaid >= Number(loan.principal)
          ? "PAID"
          : "ACTIVE";

      await pool.query(
        `UPDATE loans
         SET principal_paid = $1,
             status = $2
         WHERE id = $3`,
        [
          newPrincipalPaid,
          newStatus,
          loanId
        ]
      );

      const repaymentResult = await pool.query(
        `INSERT INTO loan_repayments
          (loan_id, amount, repayment_date, notes)
         VALUES($1, $2, COALESCE($3, CURRENT_DATE), $4)
         RETURNING *`,
        [
          loanId,
          repayment,
          req.body.repayment_date || null,
          req.body.notes || null
        ]
      );

      await pool.query(
        `INSERT INTO transactions
          (member_id, transaction_type, amount,
           description, reference_id, transaction_date)
         VALUES($1, 'LOAN_REPAYMENT', $2, $3, $4,
           COALESCE($5, CURRENT_DATE))`,
        [
          loan.member_id,
          repayment,
          "Loan repayment",
          loanId,
          req.body.repayment_date || null
        ]
      );

      await pool.query(
        `INSERT INTO audit_logs
          (user_id, action, entity_type, entity_id, details)
         VALUES($1, 'CREATE', 'LOAN_REPAYMENT', $2, $3)`,
        [
          req.user.id,
          loanId,
          `Recorded repayment of ${repayment}`
        ]
      );

      res.status(201).json({
        repayment: repaymentResult.rows[0],
        remaining:
          Number(loan.principal) -
          newPrincipalPaid
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to record repayment"
      });
    }
  }
);

// --------------------------------------------------
// INVESTMENTS
// --------------------------------------------------

app.get("/api/investments", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM investments
      ORDER BY current_value DESC, name
    `);

    const investments = result.rows.map(i => ({
      ...i,
      gain:
        Number(i.current_value || 0) -
        Number(i.purchase_price || 0),
      gain_percent:
        Number(i.purchase_price || 0) > 0
          ? (
              (
                Number(i.current_value || 0) -
                Number(i.purchase_price || 0)
              ) /
              Number(i.purchase_price)
            ) * 100
          : 0
    }));

    res.json(investments);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load investments"
    });
  }
});

app.post(
  "/api/investments",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        name,
        type,
        units,
        purchase_price,
        current_value,
        purchase_date,
        notes
      } = req.body;

      if (!name) {
        return res.status(400).json({
          error: "Investment name is required"
        });
      }

      const purchase =
        Number(purchase_price || 0);

      const current =
        Number(
          current_value !== undefined
            ? current_value
            : purchase
        );

      const result = await pool.query(
        `INSERT INTO investments
          (name, type, units, purchase_price,
           current_value, purchase_date, notes)
         VALUES($1, $2, $3, $4, $5,
           COALESCE($6, CURRENT_DATE), $7)
         RETURNING *`,
        [
          name,
          type || "OTHER",
          Number(units || 0),
          purchase,
          current,
          purchase_date || null,
          notes || null
        ]
      );

      const investment = result.rows[0];

      await pool.query(
        `INSERT INTO transactions
          (transaction_type, amount, description,
           reference_id, transaction_date)
         VALUES(
           'INVESTMENT_PURCHASE',
           $1,
           $2,
           $3,
           COALESCE($4, CURRENT_DATE)
         )`,
        [
          purchase,
          `Investment purchase: ${name}`,
          investment.id,
          purchase_date || null
        ]
      );

      await pool.query(
        `INSERT INTO investment_values
          (investment_id, value, value_date)
         VALUES($1, $2, COALESCE($3, CURRENT_DATE))`,
        [
          investment.id,
          current,
          purchase_date || null
        ]
      );

      await pool.query(
        `INSERT INTO audit_logs
          (user_id, action, entity_type, entity_id, details)
         VALUES($1, 'CREATE', 'INVESTMENT', $2, $3)`,
        [
          req.user.id,
          investment.id,
          `Created investment ${name}`
        ]
      );

      res.status(201).json(investment);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to create investment"
      });
    }
  }
);

app.post(
  "/api/investments/:id/value",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const investmentId =
        Number(req.params.id);

      const value =
        Number(req.body.value);

      if (!Number.isFinite(value) || value < 0) {
        return res.status(400).json({
          error: "Valid value is required"
        });
      }

      const result = await pool.query(
        `UPDATE investments
         SET current_value = $1
         WHERE id = $2
         RETURNING *`,
        [value, investmentId]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Investment not found"
        });
      }

      await pool.query(
        `INSERT INTO investment_values
          (investment_id, value, value_date)
         VALUES($1, $2, COALESCE($3, CURRENT_DATE))`,
        [
          investmentId,
          value,
          req.body.value_date || null
        ]
      );

      await pool.query(
        `INSERT INTO audit_logs
          (user_id, action, entity_type, entity_id, details)
         VALUES($1, 'UPDATE_VALUE', 'INVESTMENT', $2, $3)`,
        [
          req.user.id,
          investmentId,
          `Updated investment value to ${value}`
        ]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update investment value"
      });
    }
  }
);

// --------------------------------------------------
// OWNERSHIP
// --------------------------------------------------

app.get("/api/ownership", async (req, res) => {
  try {
    const nav = await calculateNAV();

    const result = await pool.query(`
      SELECT
        m.id,
        m.name,
        COALESCE(SUM(c.units), 0) AS units
      FROM members m
      LEFT JOIN contributions c
        ON c.member_id = m.id
      WHERE m.active = TRUE
      GROUP BY m.id, m.name
      ORDER BY units DESC, m.name
    `);

    const ownership = result.rows.map(row => {
      const units = Number(row.units || 0);

      return {
        id: row.id,
        name: row.name,
        units,
        ownership_percent:
          nav.totalUnits > 0
            ? (units / nav.totalUnits) * 100
            : 0,
        value:
          units * nav.unitPrice
      };
    });

    res.json({
      nav,
      ownership
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load ownership"
    });
  }
});

// --------------------------------------------------
// TRANSACTIONS
// --------------------------------------------------

app.get("/api/transactions", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        t.*,
        m.name AS member_name
      FROM transactions t
      LEFT JOIN members m
        ON m.id = t.member_id
      ORDER BY t.transaction_date DESC, t.id DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load transactions"
    });
  }
});

// --------------------------------------------------
// AUDIT LOG
// --------------------------------------------------

app.get(
  "/api/audit",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          a.*,
          u.email
        FROM audit_logs a
        LEFT JOIN users u
          ON u.id = a.user_id
        ORDER BY a.created_at DESC
        LIMIT 500
      `);

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load audit log"
      });
    }
  }
);

// --------------------------------------------------
// NAV SNAPSHOT
// --------------------------------------------------

app.post(
  "/api/nav/snapshot",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const nav = await calculateNAV();

      const result = await pool.query(
        `INSERT INTO nav_snapshots
          (nav, units, unit_price, snapshot_date)
         VALUES($1, $2, $3, COALESCE($4, CURRENT_DATE))
         RETURNING *`,
        [
          nav.nav,
          nav.totalUnits,
          nav.unitPrice,
          req.body.snapshot_date || null
        ]
      );

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to create NAV snapshot"
      });
    }
  }
);

// --------------------------------------------------
// STATIC FRONTEND
// --------------------------------------------------

// index.html is in the SAME directory as server.js
app.use(express.static(__dirname));

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((error, req, res, next) => {
  console.error(error);

  res.status(500).json({
    error: "Internal server error"
  });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

async function start() {
  try {
    await init();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Kirathimo server running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Failed to start Kirathimo:",
      error
    );

    process.exit(1);
  }
}

start();
