from google.cloud import bigquery
from google.cloud.bigquery import QueryJobConfig, ScalarQueryParameter
from google.oauth2 import service_account
import os
import json
from typing import List, Dict, Optional, Any
from datetime import datetime

BG_MASTER_TABLE = "gostlm.gost_bq.vulnerabilities_master"
BG_VULNERABILITIES_TABLE = "gostlm.gost_bq.vulnerabilities_light"
BG_GLOBAL_SEVERITY_STATE_TABLE = "gostlm.gost_bq.global_severity_state_service"
BG_MARKET_SEVERITY_STATE_TABLE = "gostlm.gost_bq.markets_severity_state_service"
BG_GLOBAL_KPI_SUMMARY = "gostlm.gost_bq.global_kpi_summary"
BG_MARKET_KPI_SUMMARY = "gostlm.gost_bq.market_kpi_summary"
BG_VULNS_TIME_TO_OVERDUE = "gostlm.gost_bq.vulnerabilities_time_to_overdue"
BG_GLOBAL_CURRENT_RISK_SUMMARY = "gostlm.gost_bq.global_current_risk_summary"
BG_MARKET_CURRENT_RISK_SUMMARY = "gostlm.gost_bq.market_current_risk_summary"
BG_VULNS_STATE_CLOSED = "gostlm.gost_bq.state_closed"
BG_VULNS_STATE_OPEN = "gostlm.gost_bq.state_open"
BG_VULNS_STATE_PARKED = "gostlm.gost_bq.state_parked"
BG_VULNS_STATE_VALIDATING = "gostlm.gost_bq.state_validating"
BG_LAST_UPDATE = "gostlm.gost_bq.update_history"

def get_bq_client():
    key_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if key_path and os.path.exists(key_path):
        creds = service_account.Credentials.from_service_account_file(key_path)
        return bigquery.Client(credentials=creds, project=creds.project_id)
    # On GCE with attached SA
    return bigquery.Client()

def list_tables(dataset: str) -> List[str]:
    client = get_bq_client()
    return [t.table_id for t in client.list_tables(dataset)]

def get_table_schema(fully_qualified: str) -> Dict:
    client = get_bq_client()
    table = client.get_table(fully_qualified)
    return {
        "table": fully_qualified,
        "schema": [{"name": s.name, "type": s.field_type, "mode": s.mode} for s in table.schema],
    }

def run_sql(sql: str, params: Optional[Dict[str, Any]] = None, max_results: int = 100):
    """
    Runs a SQL query, now with support for query parameters to prevent SQL injection.
    """
    client = get_bq_client()
    job_config = QueryJobConfig()

    if params:
        query_params = []
        for key, value in params.items():
            # Infer type for BigQuery parameter
            param_type = "STRING"
            if isinstance(value, bool):
                param_type = "BOOL"
            elif isinstance(value, int):
                param_type = "INT64"
            elif isinstance(value, float):
                param_type = "FLOAT64"
            elif isinstance(value, datetime):
                param_type = "TIMESTAMP"

            query_params.append(ScalarQueryParameter(key, param_type, value))
        job_config.query_parameters = query_params

    job = client.query(sql, job_config=job_config)
    rows = list(job.result(max_results=max_results))
    cols = [schema.name for schema in job.result().schema]
    data = [list(row) for row in rows]
    return {"columns": cols, "rows": data}


def log_sql_query_to_bq(query: str):
    """
    Inserts a single SQL query string into the OLD log table.
    """
    try:
        log_table_id = os.getenv("BG_AUDIT_LOG_TABLE")
        if not log_table_id:
            print("Warning: BG_AUDIT_LOG_TABLE environment variable not set. Skipping log.")
            return

        client = get_bq_client()
        rows_to_insert = [{"query": query}]
        errors = client.insert_rows_json(log_table_id, rows_to_insert)
        if errors:
            print(f"Error logging SQL query to BigQuery: {errors}")
    except Exception as e:
        print(f"CRITICAL: Failed to log SQL query to BigQuery: {e}")


def log_audit_event_to_bq(
        conversation_id: str,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict] = None,
        tool_response: Optional[str] = None,  # Expects JSON string
        final_response: Optional[str] = None
):
    """
    Logs a full audit event (tool call or final response) to the new events table.
    """
    try:
        log_table_id = os.getenv("BG_AUDIT_LOG_TABLE_EVENTS")
        if not log_table_id:
            print("Warning: BG_AUDIT_LOG_TABLE_EVENTS env var not set. Skipping audit.")
            return

        client = get_bq_client()

        # Serialize args if they are a dict
        args_str = None
        if isinstance(tool_args, dict):
            args_str = json.dumps(tool_args)
        elif isinstance(tool_args, str):
            args_str = tool_args

        rows_to_insert = [
            {
                "event_timestamp": datetime.utcnow().isoformat(),
                "conversation_id": conversation_id,
                "tool_name": tool_name,
                "tool_args": args_str,
                "tool_response": tool_response,
                "final_response": final_response,
            }
        ]

        errors = client.insert_rows_json(log_table_id, rows_to_insert)
        if errors:
            print(f"Error logging audit event to BigQuery: {errors}")
        else:
            print(f"Successfully logged audit event for {conversation_id}")

    except Exception as e:
        print(f"CRITICAL: Failed to log audit event to BigQuery: {e}")
