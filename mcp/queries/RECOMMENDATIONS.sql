WITH
  -- Step 1: Filter for active vulnerabilities and calculate their individual risk score.
  -- NO GROUP BY here. This CTE now contains one row for each matching vulnerability.
  active_vulns_with_score AS (
    SELECT
      vuln_type,
      severity,
      state,
      recommendations,
      CASE
        WHEN time_to_solve_days > 0 THEN SAFE_DIVIDE(total_open_days, time_to_solve_days)
        ELSE NULL
      END AS individual_risk_score
    FROM
      `{BG_MASTER_TABLE}`
    WHERE
      service IN ('White Box', 'Black Box')
      AND severity != 'Info'
      AND vuln_type IS NOT NULL
  ),

  -- Step 2: Calculate the risk and all other stats, grouping by vuln_type
  vuln_type_risk AS (
    SELECT
      vuln_type,
      COUNT(*) AS total_active_vulnerabilities,
      ROUND(AVG(individual_risk_score), 2) AS average_risk_score,
      ARRAY_AGG(DISTINCT recommendations IGNORE NULLS) AS recommendation_list,
      COUNTIF(severity = 'Critical') as Critical,
      COUNTIF(severity = 'High') as High,
      COUNTIF(severity = 'Medium') as Medium,
      COUNTIF(severity = 'Low') as Low,
      COUNTIF(severity = 'Critical' AND state IN ('New', 'Open', 'Validating')) as Critical_Open,
      COUNTIF(severity = 'High' AND state IN ('New', 'Open', 'Validating')) as High_Open,
      COUNTIF(severity = 'Medium' AND state IN ('New', 'Open', 'Validating')) as Medium_Open,
      COUNTIF(severity = 'Low' AND state IN ('New', 'Open', 'Validating')) as Low_Open
    FROM
      active_vulns_with_score
    GROUP BY
      vuln_type
  ),

  -- Step 3: Calculate the same stats for the 'Total'
  total_risk AS (
    SELECT
      'Total' AS vuln_type,
      COUNT(*) AS total_active_vulnerabilities,
      ROUND(AVG(individual_risk_score), 2) AS average_risk_score,
      ARRAY_AGG(DISTINCT recommendations IGNORE NULLS) AS recommendation_list,
      COUNTIF(severity = 'Critical') as Critical,
      COUNTIF(severity = 'High') as High,
      COUNTIF(severity = 'Medium') as Medium,
      COUNTIF(severity = 'Low') as Low,
      COUNTIF(severity = 'Critical' AND state IN ('New', 'Open', 'Validating')) as Critical_Open,
      COUNTIF(severity = 'High' AND state IN ('New', 'Open', 'Validating')) as High_Open,
      COUNTIF(severity = 'Medium' AND state IN ('New', 'Open', 'Validating')) as Medium_Open,
      COUNTIF(severity = 'Low' AND state IN ('New', 'Open', 'Validating')) as Low_Open
    FROM
      active_vulns_with_score
    -- No GROUP BY, so it aggregates all rows from the first CTE
  )
  
-- Combine the category results with the total results.
SELECT * FROM vuln_type_risk
UNION ALL
SELECT * FROM total_risk
ORDER BY
  -- This puts 'Total' at the bottom, and orders the rest by risk score.
  CASE WHEN vuln_type = 'Total' THEN 1 ELSE 0 END,
  average_risk_score DESC,
  total_active_vulnerabilities DESC;