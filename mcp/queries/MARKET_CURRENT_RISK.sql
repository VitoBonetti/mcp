SELECT
    kpi_category,
    total_active_vulnerabilities,
    average_risk_score
FROM
    `{BG_MARKET_CURRENT_RISK_SUMMARY}`
WHERE
    LOWER(market) LIKE LOWER(@market)