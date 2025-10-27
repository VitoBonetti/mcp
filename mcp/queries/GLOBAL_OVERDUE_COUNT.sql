SELECT
    is_overdue,
    COUNT(*) AS vulnerability_count
FROM
    `{BG_MASTER_TABLE}`
GROUP BY
   is_overdue