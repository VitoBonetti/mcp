SELECT
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS Critical,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS High,
    SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) AS Medium,
    SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) AS Low,
    SUM(CASE WHEN severity = 'Info' THEN 1 ELSE 0 END) AS Info
FROM
    `{BG_MASTER_TABLE}`
WHERE
    LOWER(market) LIKE LOWER(@market)