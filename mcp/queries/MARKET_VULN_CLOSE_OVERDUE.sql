SELECT
  id,
  time_to_solve_days,
  ROUND(total_open_days,2) AS open_days,
  description,
  market,
  severity,
  state,
  sub_state,
  details_summary,
  last_comment_at,
  last_comment_by,
  last_comment,
  vuln_url,
  ROUND((time_to_solve_days - total_open_days), 2) AS remain_time
FROM
  `{BG_MASTER_TABLE}`
WHERE
  NOT is_overdue
  AND state IN ('Open', 'New', 'Validating')
  AND (time_to_solve_days - total_open_days) < 7
  AND LOWER(market) LIKE LOWER(@market)
ORDER BY
  CASE severity
    WHEN 'Critical' THEN 1
    WHEN 'High'     THEN 2
    WHEN 'Medium'   THEN 3
    WHEN 'Low'      THEN 4
    WHEN 'Info'     THEN 5
    ELSE 6
  END,
  remain_time
