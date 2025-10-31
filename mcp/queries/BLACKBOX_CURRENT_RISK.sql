WITH
  -- Filter for active vulnerabilities and calculate their individual risk score.
  active_vulns_with_score AS (
    SELECT
      CASE
        WHEN severity IN ('Critical', 'High') THEN 'High'
        WHEN severity IN ('Medium', 'Low', 'Info') THEN 'Low'
      END AS kpi_category,
      CASE
        WHEN time_to_solve_days > 0 THEN SAFE_DIVIDE(total_open_days, time_to_solve_days)
        ELSE NULL
      END AS individual_risk_score
    FROM
      `{BG_MASTER_TABLE}`
    WHERE
      state NOT IN ('Closed', 'Parked')
      AND service = 'Black Box'
  ),
  -- Calculate the risk for the 'High' and 'Low' categories, as before.
  category_risk AS (
    SELECT
      kpi_category,
      COUNT(*) AS total_active_vulnerabilities,
      ROUND(SUM(individual_risk_score) / COUNT(individual_risk_score),2) AS average_risk_score
    FROM
      active_vulns_with_score
    GROUP BY
      kpi_category
  ),
  --  Calculate the risk for the 'Total'
  total_risk AS (
    SELECT
      'Total' AS kpi_category, -- We manually assign the category name 'Total'
      COUNT(*) AS total_active_vulnerabilities,
      ROUND(SUM(individual_risk_score) / COUNT(individual_risk_score),2) AS average_risk_score
    FROM
      active_vulns_with_score
  )
-- Combine the category results with the total results.
SELECT * FROM category_risk
UNION ALL
SELECT * FROM total_risk
ORDER BY
  CASE kpi_category
    WHEN 'High' THEN 1
    WHEN 'Low' THEN 2
    WHEN 'Total' THEN 3
  END;