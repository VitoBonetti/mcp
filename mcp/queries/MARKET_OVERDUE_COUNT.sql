SELECT
    is_overdue,
    COUNT(*) AS vulnerability_count
FROM
    `{BG_MASTER_TABLE}`
WHERE
    LOWER(market) LIKE LOWER(@market)
GROUP BY
   is_overdue