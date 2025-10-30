WITH
  -- Filter for active vulnerabilities and calculate their individual risk score.
  -- Now selects vuln_type instead of kpi_category.
  active_vulns_with_score AS (
    SELECT
      vuln_type, -- Select the vuln_type to group by
      CASE
        WHEN time_to_solve_days > 0 THEN SAFE_DIVIDE(total_open_days, time_to_solve_days)
        ELSE NULL
      END AS individual_risk_score
    FROM
      `{BG_MASTER_TABLE}`
    WHERE
      service IN ('White Box', 'Black Box')
      AND severity != 'Info'
      AND vuln_type IS NOT NULL -- Added to avoid a 'NULL' group
  ),
  -- Calculate the risk, grouping by vuln_type
  vuln_type_risk AS (
    SELECT
      vuln_type,
      COUNT(*) AS total_active_vulnerabilities,
      ROUND(AVG(individual_risk_score), 2) AS average_risk_score
    FROM
      active_vulns_with_score
    GROUP BY
      vuln_type
  ),
  -- Calculate the risk for the 'Total'
  total_risk AS (
    SELECT
      'Total' AS vuln_type, -- We manually assign the category name 'Total'
      COUNT(*) AS total_active_vulnerabilities,
      ROUND(AVG(individual_risk_score), 2) AS average_risk_score
    FROM
      active_vulns_with_score
  )
-- Combine the category results with the total results.
SELECT * FROM vuln_type_risk
UNION ALL
SELECT * FROM total_risk
ORDER BY
  -- A new ORDER BY clause:
  -- This puts 'Total' at the bottom, and orders the rest by risk score.
  CASE WHEN vuln_type = 'Total' THEN 1 ELSE 0 END,
  average_risk_score DESC;