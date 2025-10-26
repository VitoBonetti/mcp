SELECT
    SUM(CASE WHEN state in ('New', 'Open', 'Validating') THEN 1 ELSE 0 END) AS Open,
    SUM(CASE WHEN state in ('Closed', 'Parked') THEN 1 ELSE 0 END) AS Closed
FROM
    `{BG_MASTER_TABLE}`