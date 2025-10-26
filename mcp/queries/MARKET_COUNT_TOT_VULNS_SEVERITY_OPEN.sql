SELECT
    SUM(CASE WHEN severity = 'Critical' AND state IN ('New', 'Open', 'Validating') THEN 1 ELSE 0 END) AS Critical,
    SUM(CASE WHEN severity = 'High' AND state IN ('New', 'Open', 'Validating') THEN 1 ELSE 0 END) AS High,
    SUM(CASE WHEN severity = 'Medium' AND state IN ('New', 'Open', 'Validating') THEN 1 ELSE 0 END) AS Medium,
    SUM(CASE WHEN severity = 'Low' AND state IN ('New', 'Open', 'Validating') THEN 1 ELSE 0 END) AS Low,
    SUM(CASE WHEN severity = 'Info' AND state IN ('New', 'Open', 'Validating') THEN 1 ELSE 0 END) AS Info
FROM
  `{BG_MASTER_TABLE}`
WHERE
    LOWER(market) LIKE LOWER(@market)