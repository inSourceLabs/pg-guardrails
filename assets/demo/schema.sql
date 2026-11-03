-- Demo schema for pg-guardrails. Synthetic data only.
DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;
DROP TABLE IF EXISTS customers CASCADE;

CREATE TABLE customers (
    customer_id  INTEGER PRIMARY KEY,
    full_name    TEXT NOT NULL,
    phone        TEXT NOT NULL,
    national_id  TEXT NOT NULL,
    county       TEXT NOT NULL,
    segment      TEXT NOT NULL,
    credit_score INTEGER NOT NULL
);

CREATE TABLE accounts (
    account_id   INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(customer_id),
    account_type TEXT NOT NULL,
    balance_kes  BIGINT NOT NULL,
    opened_date  DATE NOT NULL,
    status       TEXT NOT NULL
);

CREATE TABLE transactions (
    txn_id      BIGINT PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(account_id),
    ts          TIMESTAMPTZ NOT NULL,
    channel     TEXT NOT NULL,
    amount_kes  BIGINT NOT NULL,
    direction   TEXT NOT NULL CHECK (direction IN ('in','out')),
    status      TEXT NOT NULL,
    risk_score  NUMERIC(4,1) NOT NULL
);
