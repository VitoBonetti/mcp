SELECT
  market,
  COUNT(*) AS total,
  COUNTIF(severity = 'Critical') AS Critical,
  COUNTIF(severity = 'High') AS High,
  COUNTIF(severity = 'Medium') AS Medium,
  COUNTIF(severity = 'Low') AS Low,
  COUNTIF(severity = 'Info') AS Info,
  COUNTIF(severity = 'Critical' AND state IN ('New', 'Open', 'Validating')) AS Critical_Open,
  COUNTIF(severity = 'High' AND state IN ('New', 'Open', 'Validating')) AS High_Open,
  COUNTIF(severity = 'Medium' AND state IN ('New', 'Open', 'Validating')) AS Medium_Open,
  COUNTIF(severity = 'Low' AND state IN ('New', 'Open', 'Validating')) AS Low_Open,
  COUNTIF(severity = 'Info' AND state IN ('New', 'Open', 'Validating')) AS Info_Open,
  COUNTIF(state IN ('New', 'Open', 'Validating')) AS total_open,
FROM
  `{BG_MASTER_TABLE}`
GROUP BY
  market
ORDER BY
  total DESC,
  total_open DESC,
  Critical_Open DESC
LIMIT 6
