INSERT INTO customers (customer_id, full_name, phone, national_id, county, segment, credit_score)
SELECT g, 'Customer ' || g, '+2547' || lpad(g::text, 7, '0'), 'ID' || g,
       (ARRAY['Nairobi','Kisumu','Mombasa','Nakuru'])[1 + g % 4],
       (ARRAY['retail','sme','corporate'])[1 + g % 3],
       300 + (g * 37) % 600
FROM generate_series(1, 500) g;

INSERT INTO accounts (account_id, customer_id, account_type, balance_kes, opened_date, status)
SELECT g, 1 + g % 500, (ARRAY['current','savings','mobile_money'])[1 + g % 3],
       (g * 12345) % 5000000, DATE '2019-01-01' + (g % 900), 'active'
FROM generate_series(1, 1200) g;

INSERT INTO transactions (txn_id, account_id, ts, channel, amount_kes, direction, status, risk_score)
SELECT g, 1 + g % 1200,
       TIMESTAMPTZ '2025-01-01 00:00:00Z' + (g % 40000) * interval '1 minute',
       (ARRAY['bank_transfer','mobile_money','atm','card'])[1 + g % 4],
       100 + (g * 97) % 49900,
       (CASE WHEN g % 3 = 0 THEN 'in' ELSE 'out' END),
       (CASE WHEN g % 50 = 0 THEN 'failed' ELSE 'success' END),
       (g % 100)::numeric(4,1)
FROM generate_series(1, 20000) g;
