SELECT
    severity,
    CASE severity
        WHEN 'Critical' THEN 14
        WHEN 'High'     THEN 30
        WHEN 'Medium'   THEN 45
        WHEN 'Low'      THEN 60
        WHEN 'Info'     THEN 270
        ELSE NULL
    END AS time_to_solve,
    ROUND(AVG(total_open_days), 2) AS avg_open_days
FROM
    `{BG_MASTER_TABLE}`
WHERE
    state IN ('New', 'Open', 'Validating')
GROUP BY
    severity
ORDER BY
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        WHEN 'Low'      THEN 4
        WHEN 'Info'     THEN 5
        ELSE 6
    END
