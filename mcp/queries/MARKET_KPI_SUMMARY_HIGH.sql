SELECT
    total_vulnerabilities,
    on_time_resolved_count,
    still_in_play_count,
    overdue_open_count,
    kpi_goal_percentage,
    kpi_actual_percentage,
    kpi_status,
    still_in_play_percentage,
    overdue_open_percentage,
    overdue_closed_parked_percentage,
    is_kpi_reachable
FROM
    `{BG_MARKET_KPI_SUMMARY}`
WHERE
    kpi_category = 'High'
    AND LOWER(market) LIKE LOWER(@market)