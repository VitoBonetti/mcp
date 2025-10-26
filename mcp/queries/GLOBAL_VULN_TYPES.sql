WITH VulnerabilityCounts AS (
SELECT
    vuln_type,
    COUNTIF(severity = 'Critical') AS Critical,
    COUNTIF(severity = 'High') AS High,
    COUNTIF(severity = 'Medium') AS Medium,
    COUNTIF(severity = 'Low') AS Low,
    COUNTIF(severity = 'Info') AS Info,
    COUNT(*) AS total_found,
    COUNTIF(severity = 'Critical' AND state IN ('New', 'Open', 'Validating')) AS Critical_Open,
    COUNTIF(severity = 'High' AND state IN ('New', 'Open', 'Validating')) AS High_Open,
    COUNTIF(severity = 'Medium' AND state IN ('New', 'Open', 'Validating')) AS Medium_Open,
    COUNTIF(severity = 'Low' AND state IN ('New', 'Open', 'Validating')) AS Low_Open,
    COUNTIF(severity = 'Info' AND state IN ('New', 'Open', 'Validating')) AS Info_Open,
FROM
    `{BG_MASTER_TABLE}`
WHERE
    vuln_type IS NOT NULL
GROUP BY
    vuln_type
)
SELECT
  vuln_type,
  total_found,
  Critical,
  High,
  Medium,
  Low,
  Info,
  Critical_Open,
  High_Open,
  Medium_Open,
  Low_Open,
  Info_Open
FROM
  VulnerabilityCounts
ORDER BY
  total_found DESC
LIMIT 15


