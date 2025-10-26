SELECT
  FORMAT_DATETIME("%b", published_at) as published_month,
  DATE_TRUNC(published_at, MONTH) AS month_start,
  COUNT(*) AS item_count
FROM
  `{BG_MASTER_TABLE}`
WHERE
    LOWER(market) LIKE LOWER(@market)
GROUP BY
  published_month, month_start
ORDER BY
  month_start ASC