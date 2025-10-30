SELECT
  vuln_type,
  STRING_AGG(DISTINCT recommendations, "\n\n") AS combined_recommendations,
  COUNT(*) AS type_count
FROM
  `{BG_MASTER_TABLE}`
WHERE
  severity != 'Info'
  AND service in ('White Box', 'Black Box')
GROUP BY
  vuln_type
ORDER BY
  type_count DESC
