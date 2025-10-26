import os
import uuid
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import io
import base64
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.cloud import storage
from bigquery_client import run_sql
from bigquery_client import (
    BG_MASTER_TABLE,
    BG_VULNERABILITIES_TABLE,
    BG_GLOBAL_SEVERITY_STATE_TABLE,
    BG_MARKET_SEVERITY_STATE_TABLE,
    BG_GLOBAL_KPI_SUMMARY,
    BG_MARKET_KPI_SUMMARY,
    BG_VULNS_TIME_TO_OVERDUE,
    BG_GLOBAL_CURRENT_RISK_SUMMARY,
    BG_MARKET_CURRENT_RISK_SUMMARY,
    BG_VULNS_STATE_CLOSED,
    BG_VULNS_STATE_OPEN,
    BG_VULNS_STATE_PARKED,
    BG_VULNS_STATE_VALIDATING,
    BG_LAST_UPDATE
)

# Define directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
QUERY_DIR = os.path.join(BASE_DIR, "queries")
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")

# Set up Jinja2 environment
jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
gcs_client = storage.Client()
gcs_bucket = gcs_client.bucket(GCS_BUCKET_NAME) if GCS_BUCKET_NAME else None

# --- SQL Query Loader ---
# This dictionary maps query names to their file names
QUERY_FILES = {
    "GLOBAL_AVERAGE_TIME_PER_SEVERITY_CLOSED": "GLOBAL_AVERAGE_TIME_PER_SEVERITY_CLOSED.sql",
    "GLOBAL_AVERAGE_TIME_PER_SEVERITY_OPEN": "GLOBAL_AVERAGE_TIME_PER_SEVERITY_OPEN.sql",
    "GLOBAL_COUNT_CRITICAL_HIGH_OPEN": "GLOBAL_COUNT_CRITICAL_HIGH_OPEN.sql",
    "GLOBAL_COUNT_TOT_VULNS": "GLOBAL_COUNT_TOT_VULNS.sql",
    "GLOBAL_COUNT_TOT_VULNS_OPEN_CLOSED": "GLOBAL_COUNT_TOT_VULNS_OPEN_CLOSED.sql",
    "GLOBAL_COUNT_TOT_VULNS_SEVERITY": "GLOBAL_COUNT_TOT_VULNS_SEVERITY.sql",
    "GLOBAL_COUNT_TOT_VULNS_SEVERITY_OPEN": "GLOBAL_COUNT_TOT_VULNS_SEVERITY_OPEN.sql",
    "GLOBAL_COUNT_VULN_CLOSE_OVERDUE": "GLOBAL_COUNT_VULN_CLOSE_OVERDUE.sql",
    "GLOBAL_CRITICAL_HIGH_OPEN": "GLOBAL_CRITICAL_HIGH_OPEN.sql",
    "GLOBAL_CURRENT_RISK": "GLOBAL_CURRENT_RISK.sql",
    "GLOBAL_KPI_SUMMARY_HIGH": "GLOBAL_KPI_SUMMARY_HIGH.sql",
    "GLOBAL_KPI_SUMMARY_LOW": "GLOBAL_KPI_SUMMARY_LOW.sql",
    "GLOBAL_MONTHLY_TREND": "GLOBAL_MONTHLY_TREND.sql",
    "GLOBAL_SERVICE_MONTHLY_TREND": "GLOBAL_SERVICE_MONTHLY_TREND.sql",
    "GLOBAL_VULN_CLOSE_OVERDUE": "GLOBAL_VULN_CLOSE_OVERDUE.sql",
    "GLOBAL_VULN_TYPES": "GLOBAL_VULN_TYPES.sql",
    "LAST_UPDATE": "LAST_UPDATE.sql",
    "MARKET_AVERAGE_TIME_PER_SEVERITY_CLOSED": "MARKET_AVERAGE_TIME_PER_SEVERITY_CLOSED.sql",
    "MARKET_AVERAGE_TIME_PER_SEVERITY_OPEN": "MARKET_AVERAGE_TIME_PER_SEVERITY_OPEN.sql",
    "MARKET_COUNT_CRITICAL_HIGH_OPEN": "MARKET_COUNT_CRITICAL_HIGH_OPEN.sql",
    "MARKET_COUNT_TOT_VULNS": "MARKET_COUNT_TOT_VULNS.sql",
    "MARKET_COUNT_TOT_VULNS_OPEN_CLOSED": "MARKET_COUNT_TOT_VULNS_OPEN_CLOSED.sql",
    "MARKET_COUNT_TOT_VULNS_SEVERITY": "MARKET_COUNT_TOT_VULNS_SEVERITY.sql",
    "MARKET_COUNT_TOT_VULNS_SEVERITY_OPEN": "MARKET_COUNT_TOT_VULNS_SEVERITY_OPEN.sql",
    "MARKET_COUNT_VULN_CLOSE_OVERDUE": "MARKET_COUNT_VULN_CLOSE_OVERDUE.sql",
    "MARKET_CRITICAL_HIGH_OPEN": "MARKET_CRITICAL_HIGH_OPEN.sql",
    "MARKET_CURRENT_RISK": "MARKET_CURRENT_RISK.sql",
    "MARKET_KPI_SUMMARY_HIGH": "MARKET_KPI_SUMMARY_HIGH.sql",
    "MARKET_KPI_SUMMARY_LOW": "MARKET_KPI_SUMMARY_LOW.sql",
    "MARKET_MONTHLY_TREND": "MARKET_MONTHLY_TREND.sql",
    "MARKET_SERVICE_MONTHLY_TREND": "MARKET_SERVICE_MONTHLY_TREND.sql",
    "MARKET_VULN_CLOSE_OVERDUE": "MARKET_VULN_CLOSE_OVERDUE.sql",
    "MARKET_VULN_TYPES": "MARKET_VULN_TYPES.sql",
    "TOP_6_ASSET": "TOP_6_ASSET,sql",
    "TOP_6_MARKET": "TOP_6_MARKET,sql",
}

QUERIES = {}


def _create_avg_time_chart(title, data_rows, bar_labels=['SLA (Days)', 'Actual (Days)']):
    """
    Creates a grouped bar chart for SLA vs Average Time and returns a base64 image.
    """
    if not data_rows:
        return None

    severities = [row[0] for row in data_rows]
    sla_times = [row[1] for row in data_rows]
    avg_times = [row[2] for row in data_rows]

    x = np.arange(len(severities))  # the label locations
    width = 0.35  # the width of the bars

    # Bar colors from template
    color_sla = '#11224E'  # Dark blue
    color_avg = '#70B2B2'  # Teal

    fig, ax = plt.subplots(figsize=(8, 4))
    rects1 = ax.bar(x - width/2, sla_times, width, label=bar_labels[0], color=color_sla)
    rects2 = ax.bar(x + width/2, avg_times, width, label=bar_labels[1], color=color_avg)

    # Add some text for labels, title and axes ticks
    ax.set_ylabel('Days', fontsize=9)
    ax.set_title(title, fontsize=11, pad=5)
    ax.set_xticks(x)
    ax.set_xticklabels(severities, fontsize=8)
    ax.legend(loc='upper left', fontsize=8)

    ax.grid(True, linestyle='--', alpha=0.6, axis='y')
    ax.set_axisbelow(True) # Ensure grid is behind bars

    # Add value labels on top of each bar
    def add_labels(rects):
        for rect in rects:
            height = rect.get_height()
            if height is not None and not np.isnan(height):
                ax.annotate(f'{height:.1f}', # Format to 1 decimal place
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),  # 3 points vertical offset
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=7, fontweight='bold')

    add_labels(rects1)
    add_labels(rects2)

    # Set Y-axis limit to give space for labels
    all_values = [v for v in sla_times + avg_times if v is not None and not np.isnan(v)]
    if all_values:
        max_val = max(all_values)
        ax.set_ylim(0, max_val * 1.20) # 20% padding for labels
    else:
        ax.set_ylim(0, 10) # Default if no data

    plt.tight_layout()

    # Convert to base64
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()

    return f"data:image/png;base64,{img_base64}"


def load_query(name: str, file_name: str) -> str:
    """Loads a query from a .sql file and formats it with table names."""
    try:
        with open(os.path.join(QUERY_DIR, file_name), 'r') as f:
            # Format the query with the actual table names from the client
            return f.read().format(
                BG_MASTER_TABLE=BG_MASTER_TABLE,
                BG_VULNERABILITIES_TABLE=BG_VULNERABILITIES_TABLE,
                BG_GLOBAL_SEVERITY_STATE_TABLE=BG_GLOBAL_SEVERITY_STATE_TABLE,
                BG_MARKET_SEVERITY_STATE_TABLE=BG_MARKET_SEVERITY_STATE_TABLE,
                BG_GLOBAL_KPI_SUMMARY=BG_GLOBAL_KPI_SUMMARY,
                BG_MARKET_KPI_SUMMARY=BG_MARKET_KPI_SUMMARY,
                BG_VULNS_TIME_TO_OVERDUE=BG_VULNS_TIME_TO_OVERDUE,
                BG_GLOBAL_CURRENT_RISK_SUMMARY=BG_GLOBAL_CURRENT_RISK_SUMMARY,
                BG_MARKET_CURRENT_RISK_SUMMARY=BG_MARKET_CURRENT_RISK_SUMMARY,
                BG_VULNS_STATE_CLOSED=BG_VULNS_STATE_CLOSED,
                BG_VULNS_STATE_OPEN=BG_VULNS_STATE_OPEN,
                BG_VULNS_STATE_PARKED=BG_VULNS_STATE_PARKED,
                BG_VULNS_STATE_VALIDATING=BG_VULNS_STATE_VALIDATING,
                BG_LAST_UPDATE=BG_LAST_UPDATE
            )
    except FileNotFoundError:
        print(f"Error: Query file not found: {file_name}")
        return ""
    except Exception as e:
        print(f"Error loading query {name}: {e}")
        return ""

# Load all queries into memory on startup
for name, file_name in QUERY_FILES.items():
    QUERIES[name] = load_query(name, file_name)

def _create_avg_time_chart(title, data_rows, bar_labels=['SLA (Days)', 'Actual (Days)']):
    """
    Creates a grouped bar chart for SLA vs Average Time and returns a base64 image.
    """
    if not data_rows:
        return None

    severities = [row[0] for row in data_rows]
    sla_times = [row[1] for row in data_rows]
    avg_times = [row[2] for row in data_rows]

    x = np.arange(len(severities))  # the label locations
    width = 0.35  # the width of the bars

    # Bar colors from template
    color_sla = '#11224E'  # Dark blue
    color_avg = '#70B2B2'  # Teal

    fig, ax = plt.subplots(figsize=(8, 4))
    rects1 = ax.bar(x - width/2, sla_times, width, label=bar_labels[0], color=color_sla)
    rects2 = ax.bar(x + width/2, avg_times, width, label=bar_labels[1], color=color_avg)

    # Add some text for labels, title and axes ticks
    ax.set_ylabel('Days', fontsize=9)
    ax.set_title(title, fontsize=11, pad=5)
    ax.set_xticks(x)
    ax.set_xticklabels(severities, fontsize=8)
    ax.legend(loc='upper left', fontsize=8)

    ax.grid(True, linestyle='--', alpha=0.6, axis='y')
    ax.set_axisbelow(True) # Ensure grid is behind bars

    # Add value labels on top of each bar
    def add_labels(rects):
        for rect in rects:
            height = rect.get_height()
            if height is not None and not np.isnan(height):
                ax.annotate(f'{height:.1f}', # Format to 1 decimal place
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),  # 3 points vertical offset
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=7, fontweight='bold')

    add_labels(rects1)
    add_labels(rects2)

    # Set Y-axis limit to give space for labels
    all_values = [v for v in sla_times + avg_times if v is not None and not np.isnan(v)]
    if all_values:
        max_val = max(all_values)
        ax.set_ylim(0, max_val * 1.20) # 20% padding for labels
    else:
        ax.set_ylim(0, 10) # Default if no data

    plt.tight_layout()

    # Convert to base64
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()

    return f"data:image/png;base64,{img_base64}"


def _get_data(market: str):
    """
    Fetches a comprehensive set of data for the report concurrently.
    """
    data = {"counts": {}}
    is_global = market.lower() == "global"
    data['is_global'] = is_global

    ## Use query parameters to prevent SQL injection
    market_param = {"market": f"%{market}%"}

    # Use a ThreadPoolExecutor to run queries in parallel
    executor = ThreadPoolExecutor(max_workers=20)
    futures = {}

    # Define all queries to be run
    # --- Last update ---
    futures[executor.submit(run_sql, QUERIES["LAST_UPDATE"])] = "last_update"

    # --- KPI Queries ---
    high_kpi_sql = QUERIES["GLOBAL_KPI_SUMMARY_HIGH"] if is_global else QUERIES["MARKET_KPI_SUMMARY_HIGH"]
    low_kpi_sql = QUERIES["GLOBAL_KPI_SUMMARY_LOW"] if is_global else QUERIES["MARKET_KPI_SUMMARY_LOW"]
    futures[executor.submit(run_sql, high_kpi_sql, params=None if is_global else market_param)] = "high_kpi_details"
    futures[executor.submit(run_sql, low_kpi_sql, params=None if is_global else market_param)] = "low_kpi_details"

    # --- Top 6 Markets/Assets ---
    top_market_asset_sql = QUERIES["TOP_6_MARKET"] if is_global else QUERIES["TOP_6_ASSET"]
    futures[executor.submit(run_sql, top_market_asset_sql, params=None if is_global else market_param)] = "top_effected"

    # --- Risk Queries ---
    current_risk_sql = QUERIES["GLOBAL_CURRENT_RISK"] if is_global else QUERIES["MARKET_CURRENT_RISK"]
    futures[executor.submit(run_sql, current_risk_sql, params=None if is_global else market_param)] = "risk_summary"

    # --- Almost Overdue ---
    vuln_close_to_overdue_sql = QUERIES["GLOBAL_VULN_CLOSE_OVERDUE"] if is_global else QUERIES["MARKET_VULN_CLOSE_OVERDUE"]
    futures[executor.submit(run_sql, vuln_close_to_overdue_sql, params=None if is_global else market_param)] = "vulns_to_overdue"

    # --- Critical/High Open ---
    critical_high_open_sql = QUERIES["GLOBAL_CRITICAL_HIGH_OPEN"] if is_global else QUERIES["MARKET_CRITICAL_HIGH_OPEN"]
    futures[executor.submit(run_sql, critical_high_open_sql, params=None if is_global else market_param)] = "critical_high_open"

    # --- Vulns monthly trend ---
    vuln_tred_query = QUERIES["GLOBAL_MONTHLY_TREND"] if is_global else QUERIES["MARKET_MONTHLY_TREND"]
    futures[executor.submit(run_sql, vuln_tred_query, params=None if is_global else market_param)] = "vulns_monthly_trend"

    # --- Service monthly trend ---
    service_tred_query = QUERIES["GLOBAL_SERVICE_MONTHLY_TREND"] if is_global else QUERIES["MARKET_SERVICE_MONTHLY_TREND"]
    futures[executor.submit(run_sql, service_tred_query, params=None if is_global else market_param)] = "service_monthly_trend"

    # --- Vulnerability Types ---
    vuln_types_sql = QUERIES["GLOBAL_VULN_TYPES"] if is_global else QUERIES["MARKET_VULN_TYPES"]
    futures[executor.submit(run_sql, vuln_types_sql, params=None if is_global else market_param)] = "vuln_types"

    # --- Average Time to Solve - Closed ---
    avg_time_closed_sql = QUERIES["GLOBAL_AVERAGE_TIME_PER_SEVERITY_CLOSED"] if is_global else QUERIES["MARKET_AVERAGE_TIME_PER_SEVERITY_CLOSED"]
    futures[executor.submit(run_sql, avg_time_closed_sql, params=None if is_global else market_param)] = "avg_time_closed"

    # --- Average Time to Solve - Open ---
    avg_time_open_sql = QUERIES["GLOBAL_AVERAGE_TIME_PER_SEVERITY_OPEN"] if is_global else QUERIES["MARKET_AVERAGE_TIME_PER_SEVERITY_OPEN"]
    futures[executor.submit(run_sql, avg_time_open_sql, params=None if is_global else market_param)] = "avg_time_open"

    # --- Counts Total Vulnerabilities ---
    total_vulnerabilities_sql = QUERIES["GLOBAL_COUNT_TOT_VULNS"] if is_global else QUERIES["MARKET_COUNT_TOT_VULNS"]
    futures[executor.submit(run_sql, total_vulnerabilities_sql, params=None if is_global else market_param)] = "total_vulnerabilities_count"

    # --- Counts Total Vulnerabilities Open or Closed ---
    total_vulnerabilities_open_closed_sql = QUERIES["GLOBAL_COUNT_TOT_VULNS_OPEN_CLOSED"] if is_global else QUERIES["MARKET_COUNT_TOT_VULNS_OPEN_CLOSED"]
    futures[executor.submit(run_sql, total_vulnerabilities_open_closed_sql, params=None if is_global else market_param)] = "open_closed_count"

    # --- Counts Total Vulnerabilities per severity ---
    total_vulnerabilities_severity_sql = QUERIES["GLOBAL_COUNT_TOT_VULNS_SEVERITY"] if is_global else QUERIES["MARKET_COUNT_TOT_VULNS_SEVERITY"]
    futures[executor.submit(run_sql, total_vulnerabilities_severity_sql, params=None if is_global else market_param)] = "severities_count"

    # --- Counts Total Vulnerabilities per severity open ---
    total_vulnerabilities_severity_open_sql = QUERIES["GLOBAL_COUNT_TOT_VULNS_SEVERITY_OPEN"] if is_global else QUERIES["MARKET_COUNT_TOT_VULNS_SEVERITY_OPEN"]
    futures[executor.submit(run_sql, total_vulnerabilities_severity_open_sql, params=None if is_global else market_param)] = "severities_open_count"

    # --- Counts Total Vulnerabilities closed to overdue ---
    total_vulns_close_to_overdue_sql = QUERIES["GLOBAL_COUNT_VULN_CLOSE_OVERDUE"] if is_global else QUERIES["MARKET_COUNT_VULN_CLOSE_OVERDUE"]
    futures[executor.submit(run_sql, total_vulns_close_to_overdue_sql, params=None if is_global else market_param)] = "vulns_close_to_overdu_counte"

    # --- Counts Total Vulnerabilities Critical/High Open ---
    total_critical_high_open_sql = QUERIES["GLOBAL_COUNT_CRITICAL_HIGH_OPEN"] if is_global else QUERIES["MARKET_COUNT_CRITICAL_HIGH_OPEN"]
    futures[executor.submit(run_sql, total_critical_high_open_sql, params=None if is_global else market_param)] = "critical_high_open_count"

    # Process results as they complete
    results = {}
    for future in as_completed(futures):
        query_name = futures[future]
        try:
            results[query_name] = future.result()
        except Exception as e:
            print(f"Error running query {query_name}: {e}")
            results[query_name] = None  # Handle failures gracefully

    # --- Assemble Data ---
    # Last update
    last_update_result = results.get("last_update")
    if last_update_result and last_update_result['rows']:
        datetime_obj = last_update_result['rows'][0][0]
        last_update_date = str(datetime_obj.date())
        data['last_update'] = last_update_date
    else:
        data['last_update'] = "N/A"

    # high kpi summary
    high_kpi_result = results.get("high_kpi_details")
    data['high_kpi_details'] = {}
    if high_kpi_result and high_kpi_result['rows']:
        data['high_kpi_details'] = dict(zip(high_kpi_result['columns'], high_kpi_result['rows'][0]))

    # low kpi summary
    low_kpi_result = results.get("low_kpi_details")
    data['low_kpi_details'] = {}
    if low_kpi_result and low_kpi_result['rows']:
        data['low_kpi_details'] = dict(zip(low_kpi_result['columns'], low_kpi_result['rows'][0]))

    # top effected Market/asset
    top_effected_result = results.get("top_effected")
    data['top_effected'] = {}
    if top_effected_result and top_effected_result['rows']:
        data['top_effected'] = dict(zip(top_effected_result['columns'], top_effected_result['rows'][0]))

    # Risk Summary
    data['risk_summary'] = results.get("risk_summary", {"rows": [], "columns": []})

    # Almost Overdue
    almost_overdue_result = results.get("vulns_to_overdue")
    data['vulns_to_overdue'] = []
    if almost_overdue_result and almost_overdue_result['rows']:
        data['vulns_to_overdue'] = [
            dict(zip(almost_overdue_result['columns'], row))
            for row in almost_overdue_result['rows']
        ]

    # Critical/High Open
    critical_high_open_result = results.get("critical_high_open")
    data["high_critical_open"] = []
    if critical_high_open_result and critical_high_open_result['rows']:
        data["high_critical_open"] = [
            dict(zip(critical_high_open_result['columns'], row))
            for row in critical_high_open_result['rows']
        ]


    # Vulns monthly trend
    vulns_trend_result = results.get("vulns_monthly_trend")
    if vulns_trend_result and vulns_trend_result['rows']:
        months = [row[0] for row in vulns_trend_result['rows']]
        counts = [row[2] for row in vulns_trend_result['rows']]

        counts = np.cumsum(counts)

        plt.figure(figsize=(8, 4))
        plt.plot(months, counts, marker='o', linewidth=2)
        plt.title('Vulnerabilities Discovered per Month', fontsize=11, pad=5)
        plt.xlabel('Month', fontsize=9)
        plt.ylabel('Count', fontsize=9)
        plt.grid(True, linestyle='--', alpha=0.6)

        plt.xticks(ticks=range(len(months)), labels=months, rotation=45, ha='right', fontsize=8)
        plt.ylim(0, max(counts) * 1.1)

        for i, value in enumerate(counts):
            plt.text(
                i, value + max(counts) * 0.02,  # small offset above each point
                str(value),
                ha='center', va='bottom',
                fontsize=8, color='#11224E', fontweight='bold'
            )

        plt.tight_layout()

        # Convert to base64 image for HTML embedding
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()

        data['vulns_trend_img'] = f"data:image/png;base64,{img_base64}"
    else:
        data['vulns_trend_img'] = None

    # Service monthly trend
    service_tred_result = results.get("service_monthly_trend")
    if service_tred_result and service_tred_result['rows']:
        months = [row[0] for row in service_tred_result['rows']]
        black_box = [row[2] for row in service_tred_result['rows']]
        white_box = [row[3] for row in service_tred_result['rows']]
        adversary_sim = [row[4] for row in service_tred_result['rows']]

        black_box = np.cumsum(black_box)
        white_box = np.cumsum(white_box)
        adversary_sim = np.cumsum(adversary_sim)

        plt.figure(figsize=(8, 4))

        # Plot each line with its own color and marker
        plt.plot(months, black_box, marker='o', linewidth=2, color='black', label='Black Box')
        plt.plot(months, white_box, marker='o', linewidth=2, color='#E5B80B', label='White Box')
        plt.plot(months, adversary_sim, marker='o', linewidth=2, color='red', label='Adversary Simulation')

        plt.title('Services Engagement Over Time', fontsize=11, pad=5)
        plt.xlabel('Month', fontsize=9)
        plt.ylabel('Cumulative Engagements', fontsize=9)
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.xticks(ticks=range(len(months)), labels=months, rotation=45, ha='right', fontsize=8)
        plt.ylim(0, max(max(black_box), max(white_box), max(adversary_sim)) * 1.1)

        # Label values on top of each point
        for i, value in enumerate(black_box):
            plt.text(i, value + max(black_box) * 0.01, str(value),
                     ha='center', va='bottom', fontsize=7, color='black', fontweight='bold')
        for i, value in enumerate(white_box):
            plt.text(i, value + max(white_box) * 0.01, str(value),
                     ha='center', va='bottom', fontsize=7, color='#B08A00', fontweight='bold')
        for i, value in enumerate(adversary_sim):
            plt.text(i, value + max(adversary_sim) * 0.01, str(value),
                     ha='center', va='bottom', fontsize=7, color='darkred', fontweight='bold')

        plt.legend(loc='upper left', fontsize=8)
        plt.tight_layout()

        # Convert to base64 for embedding
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()

        data['services_trend_img'] = f"data:image/png;base64,{img_base64}"
    else:
        data['services_trend_img'] = None

    # Vulnerability Types
    vuln_types_result = results.get("vuln_types")
    data['vuln_types'] = []
    if vuln_types_result and vuln_types_result['rows']:
        data['vuln_types'] = [
            dict(zip(vuln_types_result['columns'], r))
            for r in vuln_types_result['rows']
        ]

    # Average Time to Solve - Close
    avg_time_closed_result = results.get("avg_time_closed")
    if avg_time_closed_result and avg_time_closed_result['rows']:
        data['avg_time_closed_img'] = _create_avg_time_chart(
            'Average Time to Remediate (Closed Vulns)',
            avg_time_closed_result['rows'],
            bar_labels=['SLA (Days)', 'Avg. Days to Close']
        )

    # Average Time to Solve - Open
    avg_time_open_result = results.get("avg_time_open")
    if avg_time_open_result and avg_time_open_result['rows']:
        data['avg_time_closed_img'] = _create_avg_time_chart(
            'Average Age of Open Vulnerabilities',
            avg_time_open_result['rows'],
            bar_labels=['SLA (Days)', 'Avg. Days Open']
        )

    # Counts
    tot_vulns = results.get("total_vulnerabilities_count")
    data['counts']['total_vulnerabilities'] = tot_vulns['rows'][0][0] if tot_vulns and tot_vulns['rows'] else 0

    tot_vulns_open_closed = results.get("open_closed_counts")
    data['counts']["open_closed"] = {}
    if tot_vulns_open_closed and tot_vulns_open_closed['rows']:
        data['counts']["open_closed"] = dict(zip(tot_vulns_open_closed['columns'], tot_vulns_open_closed['rows'][0]))

    tot_vuln_severity = results.get("severities_count")
    data['counts']['severities'] = {}
    if tot_vuln_severity and tot_vuln_severity['rows']:
        data['counts']['severities'] = dict(zip(tot_vuln_severity['columns'], tot_vuln_severity['rows'][0]))

    tot_vuln_severity_open = results.get("severities_open_count")
    data['counts']['severities_open'] = {}
    if tot_vuln_severity_open and tot_vuln_severity_open['rows']:
        data['counts']['severities_open'] = dict(
            zip(tot_vuln_severity_open['columns'], tot_vuln_severity_open['rows'][0]))

    vulns_close_to_overdue = results.get("vulns_close_to_overdue_count")
    data['counts']['vulns_close_to_overdue'] = {}
    if vulns_close_to_overdue and vulns_close_to_overdue['rows']:
        data['counts']['vulns_close_to_overdue'] = dict(
            zip(vulns_close_to_overdue['columns'], vulns_close_to_overdue['rows'][0]))

    total_critical_high_open = results.get("critical_high_open_count")
    data['counts']['critical_high_open'] = total_critical_high_open['rows'][0][0] if tot_vulns else 0

    return data


def generate_report(market: str) -> str:
    """
    Generates a PDF report, uploads it to GCS, and returns a
    time-limited signed URL..
    """
    print(f"Generating report for: {market}")
    if not gcs_bucket:
        raise Exception("GCS_BUCKET_NAME environment variable is not set.")

    file_name = f"VULNAI_Report_{market.replace(' ', '_')}_{uuid.uuid4()}.pdf"

    try:
        # 1. Fetch all raw data concurrently
        report_data = _get_data(market)

        # 2. Prepare template context
        context = {
            "market_name": market,
            "generated_at": str(datetime.now().isoformat(timespec='seconds')).split("T")[0],
            "data": report_data,
        }

        # 3. Load and render the HTML template
        template = jinja_env.get_template("overview_template.html")
        html_content = template.render(context)

        # 4. Convert HTML to PDF in memory
        pdf_buffer = io.BytesIO()
        HTML(string=html_content).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)

        # 5. Upload to GCS
        blob = gcs_bucket.blob(file_name)
        blob.upload_from_file(
            pdf_buffer,
            content_type='application/pdf'
        )

        print(f"Report uploaded to GCS: {file_name}")

        # 6. Generate a 5-minute signed URL
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=5),
            method="GET",
        )

        return signed_url

    except Exception as e:
        print(f"Failed to generate report: {e}")
        # Optionally, upload an error report
        error_html = f"<html><body><h1>Failed to generate report for {market}</h1><p>{e}</p></body></html>"
        pdf_buffer = io.BytesIO()
        HTML(string=error_html).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)

        blob = gcs_bucket.blob(file_name)  # Overwrite if partial
        blob.upload_from_file(pdf_buffer, content_type='application/pdf')

        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=1),
            method="GET",
        )
        # Return the error URL so the user knows something went wrong
        return f"Failed to generate report. Error log: {signed_url}"