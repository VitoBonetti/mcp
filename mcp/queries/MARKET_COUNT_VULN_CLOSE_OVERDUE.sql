SELECT
    COUNTIF(severity = 'Critical') AS Critical,
    COUNTIF(severity = 'High') AS High,
    COUNTIF(severity = 'Medium') AS Medium,
    COUNTIF(severity = 'Low') AS Low,
    COUNTIF(severity = 'Info') AS Info,
    COUNT(*) AS Total
FROM
    `{BG_MASTER_TABLE}`
WHERE
    NOT is_overdue
    AND state IN ('Open', 'New', 'Validating')
    AND (time_to_solve_days - total_open_days) < 7
    AND LOWER(market) LIKE LOWER(@market)