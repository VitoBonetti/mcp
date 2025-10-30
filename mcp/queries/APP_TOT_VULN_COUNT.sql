SELECT
    COUNT(*) as total_vuln
FROM
    `{BG_MASTER_TABLE}`
WHERE
    service in ('White Box', 'Black Box')