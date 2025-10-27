SELECT
    state,
    COUNT(*) AS vulnerability_count
FROM
    `{BG_MASTER_TABLE}`
GROUP BY
    state