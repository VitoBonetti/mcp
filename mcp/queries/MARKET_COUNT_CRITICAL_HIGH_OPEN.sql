SELECT
    COUNT(*) AS Total
FROM
    `{BG_MASTER_TABLE}`
WHERE
    state IN ('New', 'Open', 'Validating')
    AND severity IN ('Critical', 'High')
    AND LOWER(market) LIKE LOWER(@market)