import os
import uuid
from datetime import datetime, timedelta
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
from google.oauth2 import service_account
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
key_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if key_path and os.path.exists(key_path):
    creds = service_account.Credentials.from_service_account_file(key_path)
    gcs_client = storage.Client(credentials=creds, project=creds.project_id)
else:
    gcs_client = storage.Client()
gcs_bucket = gcs_client.bucket(GCS_BUCKET_NAME) if GCS_BUCKET_NAME else None

# --- SQL Query Loader ---
# This dictionary maps query names to their file names
QUERY_FILES = {
    "APP_SEVERITY_COUNT": "APP_SEVERITY_COUNT.sql",
    "APP_SEVERITY_SERVICE_COUNT": "APP_SEVERITY_SERVICE_COUNT.sql",
    "APP_CURRENT_RISK": "APP_CURRENT_RISK.sql",
    "BLACKBOX_CURRENT_RISK": "BLACKBOX_CURRENT_RISK.sql",
    "WHITEBOX_CURRENT_RISK": "WHITEBOX_CURRENT_RISK.sql",
    "APP_VULN_TYPES": "APP_VULN_TYPES.sql",
    "RECOMMENDATIONS": "RECOMMENDATIONS.sql",
    "APP_TOT_CURRENT_RISK": "APP_TOT_CURRENT_RISK.sql",
    "APP_TOT_VULN_COUNT": "APP_TOT_VULN_COUNT.sql",
    "APP_VULN_TYPES_RISK": "APP_VULN_TYPES_RISK.sql",
    "LAST_UPDATE": "LAST_UPDATE.sql",
}

QUERIES = {}


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


def _get_data():
    """
    Fetches a comprehensive set of data for the report concurrently.
    """
    data = {"counts": {}}

    # Use a ThreadPoolExecutor to run queries in parallel
    executor = ThreadPoolExecutor(max_workers=20)
    futures = {}

    # Define all queries to be run
    # --- Last update ---
    futures[executor.submit(run_sql, QUERIES["LAST_UPDATE"])] = "last_update"

    # --- Vulnerability Types ---
    vuln_types_sql = QUERIES["APP_VULN_TYPES"]
    futures[executor.submit(run_sql, vuln_types_sql, params=None)] = "vuln_types"

    # --- Counts Total Vulnerabilities ---
    total_vulnerabilities_sql = QUERIES["APP_TOT_VULN_COUNT"]
    futures[executor.submit(run_sql, total_vulnerabilities_sql, params=None)] = "total_vulnerabilities_count"

    # --- App Severity Count ---
    app_severity_count_sql = QUERIES["APP_SEVERITY_COUNT"]
    futures[executor.submit(run_sql, app_severity_count_sql, params=None)] = "app_severity_count"

    # --- App Service Count ---
    app_severity_service_count_sql = QUERIES["APP_SEVERITY_SERVICE_COUNT"]
    futures[executor.submit(run_sql, app_severity_service_count_sql, params=None)] = "app_severity_service_count"

    # --- Recommendation ---
    recommendation_sql = QUERIES["RECOMMENDATIONS"]
    futures[executor.submit(run_sql, recommendation_sql, params=None)] = "recommendation"

    # --- Risk Query ---
    # This is the actual current risk
    app_current_risk_sql = QUERIES["APP_CURRENT_RISK"]
    futures[executor.submit(run_sql, app_current_risk_sql, params=None)] = "app_current_risk"

    black_current_risk_sql = QUERIES["BLACKBOX_CURRENT_RISK"]
    futures[executor.submit(run_sql, black_current_risk_sql, params=None)] = "black_current_risk"

    white_current_risk_sql = QUERIES["WHITEBOX_CURRENT_RISK"]
    futures[executor.submit(run_sql, white_current_risk_sql, params=None)] = "white_current_risk"

    # Include closed and parked
    app_tot_current_risk_sql = QUERIES["APP_TOT_CURRENT_RISK"]
    futures[executor.submit(run_sql, app_tot_current_risk_sql, params=None)] = "app_tot_current_risk"

    app_vuln_types_risk_sql = QUERIES["APP_VULN_TYPES_RISK"]
    futures[executor.submit(run_sql, app_vuln_types_risk_sql, params=None)] = "app_vuln_types_risk"

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
        data['last_update'] = str(datetime_obj.date())
    else:
        data['last_update'] = "N/A"

    # Vuln type
    vuln_types_result = results.get("vuln_types")
    data['vuln_types'] = {}
    if vuln_types_result and vuln_types_result['rows']:
        data['vuln_types'] = dict(zip(vuln_types_result['columns'], vuln_types_result['rows'][0]))


    # Risk Summary
    data['app_current_risk'] = results.get("app_current_risk", {"rows": [], "columns": []})
    data['black_current_risk'] = results.get("black_current_risk", {"rows": [], "columns": []})
    data['white_current_risk'] = results.get("white_current_risk", {"rows": [], "columns": []})
    data['app_tot_current_risk'] = results.get("app_tot_current_risk", {"rows": [], "columns": []})
    data['app_vuln_types_risk'] = results.get("app_vuln_types_risk", {"rows": [], "columns": []})
    # Counts

    tot_vulns = results.get("total_vulnerabilities_count")
    data['counts']['total_vulnerabilities'] = tot_vulns['rows'][0][0] if tot_vulns and tot_vulns['rows'] else 0

    app_severity_count = results.get("app_severity_count")
    data['counts']["app_severity_count"] = {}
    if app_severity_count and app_severity_count['rows']:
        data['counts']["app_severity_count"] = dict(zip(app_severity_count['columns'], app_severity_count['rows'][0]))

    app_service_severity_count = results.get("app_severity_service_count")
    data['counts']["app_service_severity_count"] = []
    if app_service_severity_count and app_service_severity_count['rows']:
        columns = app_service_severity_count['columns']
        # Loop over ALL rows, not just rows[0]
        for row in app_service_severity_count['rows']:
            # Create a dictionary for each row and append it to the list
            row_dict = dict(zip(columns, row))
            data['counts']["app_service_severity_count"].append(row_dict)

    # recommendation
    recommendation_result = results.get("recommendation")
    data['recommendation'] = []
    if recommendation_result and recommendation_result['rows']:
        columns = recommendation_result['columns']
        for row in recommendation_result['rows']:
            row_dict = dict(zip(columns, row))
            data['recommendation'].append(row_dict)

    return data


def application_report():
    """
    Generates a PDF report, uploads it to GCS, and returns a
    time-limited signed URL..
    """
    print(f"Generating report")
    if not gcs_bucket:
        raise Exception("GCS_BUCKET_NAME environment variable is not set.")

    file_name = f"VULNAI_Application_Report_{uuid.uuid4()}.pdf"

    try:
        # 1. Fetch all raw data concurrently
        report_data = _get_data()

        # 2. Prepare template context
        context = {
            "generated_at": str(datetime.now().isoformat(timespec='seconds')).split("T")[0],
            "data": report_data,
        }

        # 3. Load and render the HTML template
        template = jinja_env.get_template("application_template.html")
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
        error_html = f"<html><body><h1>Failed to generate application report</h1><p>{e}</p></body></html>"
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