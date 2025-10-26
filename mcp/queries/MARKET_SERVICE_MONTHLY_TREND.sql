SELECT
  FORMAT_DATETIME("%b", published_at) as published_month,
  DATE_TRUNC(published_at, MONTH) AS month_start,
  COUNTIF(service = 'Black Box') AS black_box,
  COUNTIF(service = 'White Box') AS white_box,
  COUNTIF(service = 'Adversary Simulation') AS adversary_simulation,
FROM
  `{BG_MASTER_TABLE}`
WHERE
    LOWER(market) LIKE LOWER(@market)
GROUP BY
  published_month, month_start
ORDER BY
  month_start ASC