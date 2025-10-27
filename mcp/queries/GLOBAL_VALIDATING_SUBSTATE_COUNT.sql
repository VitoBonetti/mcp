SELECT
    COALESCE(NULLIF(sub_state, ''), 'Waiting to Retest') AS current_status,
    COUNT(*) AS vulnerability_count
FROM
    `{BG_MASTER_TABLE}`
WHERE
    state = 'Validating'
GROUP BY
    current_status
ORDER BY
    vulnerability_count DESC