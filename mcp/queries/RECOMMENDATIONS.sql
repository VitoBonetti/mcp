SELECT
    vuln_type,
    ARRAY_AGG(DISTINCT recommendations IGNORE NULLS) AS recommendation_list,
    COUNT(*) AS type_count,
    COUNTIF(severity = 'Critical') as Critical,
    COUNTIF(severity = 'High') as High,
    COUNTIF(severity = 'Medium') as Medium,
    COUNTIF(severity = 'Low') as Low,
    COUNTIF(severity = 'Critical' AND state IN ('New', 'Open', 'Validating')) as Critical_Open,
    COUNTIF(severity = 'High' AND state IN ('New', 'Open', 'Validating')) as High_Open,
    COUNTIF(severity = 'Medium' AND state IN ('New', 'Open', 'Validating')) as Medium_Open,
    COUNTIF(severity = 'Low' AND state IN ('New', 'Open', 'Validating')) as Low_Open,
FROM
    `{BG_MASTER_TABLE}`
WHERE
    severity != 'Info'
    AND service in ('White Box', 'Black Box')
GROUP BY
    vuln_type
ORDER BY
    type_count DESC
