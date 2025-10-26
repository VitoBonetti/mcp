SELECT
  id, description, severity, state, sub_state, market, vuln_url, is_overdue
FROM
  `{BG_MASTER_TABLE}`
WHERE
  state IN ('New', 'Open', 'Validating')
  AND severity IN ('Critical', 'High')
ORDER BY severity