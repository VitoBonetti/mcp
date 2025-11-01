import os
import re
import json
import uuid
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv
import google.generativeai as genai
from datetime import datetime, date

from secret_manager import get_secret
from bigquery_client import (
    list_tables, get_table_schema, run_sql,
    log_sql_query_to_bq, log_audit_event_to_bq,
    BG_VULNERABILITIES_TABLE, BG_MARKET_KPI_SUMMARY,
    BG_MARKET_SEVERITY_STATE_TABLE
)
from adk_tooling import configure_gemini, get_model, AVAILABLE_TOOLS

load_dotenv("/opt/vulnai/mcp/mcp.env")

PROJECT_ID = os.getenv("PROJECT_ID", "gostlm")
DATASET = os.getenv("BQ_DATASET", "gost_bq")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
SECRET_ID = os.getenv("GEMINI_SECRET_ID", "gemini_api_key")

# Configure Gemini from Secret Manager at startup
GEMINI_API_KEY = None
MODEL: genai.GenerativeModel = None
TOOL_MAP: Dict[str, callable] = {}

# Define your server's public-facing URL
BASE_URL = "https://vulnai.vitobonetti.nl"

app = FastAPI(title="MCP Server (ADK + BigQuery)", version="1.1.0")


# OpenAI-style request/response models
class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: Optional[str] = None
    messages: List[Message]
    stream: Optional[bool] = False
    temperature: Optional[float] = 0.0
    max_tokens: Optional[int] = 65536


class Choice(BaseModel):
    index: int
    message: Message
    finish_reason: str = "stop"


class ChatResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Choice]


class ModelItem(BaseModel):
    id: str
    object: str = "model"
    created: int | None = None
    owned_by: str = "mcp"


class ModelsResponse(BaseModel):
    object: str = "list"
    data: list[ModelItem]


def validate_sql(sql: str) -> None:
    # Basic guardrails: restrict to gostlm.gost_bq
    if re.search(r"(DELETE|UPDATE|INSERT|MERGE|DROP|ALTER)\b", sql, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Only SELECT queries are allowed.")
    if "gostlm.gost_bq" not in sql:
        raise HTTPException(status_code=400, detail="Query must reference gostlm.gost_bq tables.")


def get_function_call(response: Any) -> Optional[Any]:
    """Safely extracts a function call from a model's response."""
    if not response.candidates:
        return None
    candidate = response.candidates[0]
    if not candidate.content or not candidate.content.parts:
        return None

    # Iterate through parts to find the first function call
    for part in candidate.content.parts:
        if part.function_call:
            return part.function_call
    return None


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


@app.on_event("startup")
def on_startup():
    global GEMINI_API_KEY, MODEL, TOOL_MAP
    GEMINI_API_KEY = get_secret(PROJECT_ID, SECRET_ID, "latest")
    configure_gemini(GEMINI_API_KEY)

    # --- Pre-load key schemas ---
    print("Pre-loading key table schemas...")
    preloaded_schemas = {}
    key_tables = {
        "vulnerabilities": BG_VULNERABILITIES_TABLE,
        "market_kpi": BG_MARKET_KPI_SUMMARY,
        "market_severity": BG_MARKET_SEVERITY_STATE_TABLE
    }
    try:
        for name, table_fqn in key_tables.items():
            preloaded_schemas[name] = get_table_schema(table_fqn)
        schema_info_str = json.dumps(preloaded_schemas, indent=2)
        print("Schemas loaded successfully.")
    except Exception as e:
        print(f"CRITICAL: Failed to preload schemas: {e}")
        schema_info_str = ""

    MODEL = get_model(preloaded_schemas=schema_info_str)
    TOOL_MAP = AVAILABLE_TOOLS

    # --- summary model block ---
    global SUMMARY_MODEL
    SUMMARY_MODEL = genai.GenerativeModel(
        model_name="gemini-2.5-flash-lite"
    )
    print("Summary model initialized.")
    # --- End summary model block ---


@app.get("/healthz")
def healthz():
    return {"status": "We're cool!"}


@app.post("/v1/chat/completions", response_model=ChatResponse)
def chat(req: ChatRequest, background_tasks: BackgroundTasks):
    created = int(time.time())
    conversation_id = f"conv_{uuid.uuid4()}"

    if not MODEL or not TOOL_MAP or not SUMMARY_MODEL:
        raise HTTPException(status_code=500, detail="Model not initialized.")

    history = []
    user_query = ""

    # --- History Management ---
    # 1. Check if history is too long
    messages_to_process = req.messages
    if len(req.messages) > 10:  # e.g., 5 user, 5 model turns
        print(f"Conversation {conversation_id} has >10 messages. Attempting summarization.")
        try:
            # 2. Create a summarization request
            summarization_history = []
            for msg in req.messages[:-4]:  # Summarize all but the last 2 turns
                role = "user" if msg.role == "user" else "model"
                summarization_history.append({'role': role, 'parts': [msg.content]})

            summary_prompt = "Please provide a concise, one-paragraph summary of our conversation so far, focusing on key data points, markets, and unresolved questions. Start with 'Summary of previous conversation:'"
            summarization_history.append({'role': 'user', 'parts': [summary_prompt]})

            # 3. Generate summary (NOT as part of the main chat)
            summary_response = SUMMARY_MODEL.generate_content(
                summarization_history,
                generation_config=genai.types.GenerationConfig(temperature=0.0)
            )

            # 4. Prepend summary and keep last few messages
            summary_text = ""
            try:
                summary_text = summary_response.text
            except ValueError as e:
                print(f"Summarization response was blocked or empty: {e}")
                summary_text = f"Error during summarization: {e}"

            summary_message = {'role': 'user', 'parts': [f"<system_summary>{summary_text}</system_summary>"]}
            history.append(summary_message)
            messages_to_process = req.messages[-4:]  # Keep last 2 turns
            print(f"Summarization complete for {conversation_id}.")
        except Exception as e:
            print(f"Summarization failed for {conversation_id}: {e}. Using truncated history.")
            messages_to_process = req.messages[-10:]  # Fallback

    # 5. Build the final history for the chat session
    for msg in messages_to_process:
        role = "user" if msg.role == "user" else "model"
        history.append({'role': role, 'parts': [msg.content]})
        if msg.role == "user":
            user_query = msg.content  # Get the last user query
    # --- End History Management ---

    if not user_query:
        raise HTTPException(status_code=400, detail="No user message provided.")

    chat_session = MODEL.start_chat(history=history[:-1])

    gen_config = genai.types.GenerationConfig(
        temperature=req.temperature,
        max_output_tokens=req.max_tokens
    )

    try:
        response = chat_session.send_message(
            history[-1]['parts'],
            generation_config=gen_config
        )

        fc = get_function_call(response)

        while fc:
            if fc.name not in TOOL_MAP:
                raise HTTPException(status_code=400, detail=f"Unknown tool: {fc.name}")

            tool_function = TOOL_MAP[fc.name]
            tool_args = {key: value for key, value in fc.args.items()}

            if fc.name == "run_sql":
                sql_query = tool_args.get("sql", "")
                validate_sql(sql_query)
                print(f"SQL_QUERY_LOG: {sql_query}")
                background_tasks.add_task(log_sql_query_to_bq, sql_query)  # Log to old table
            else:
                print(f"Running tool: {fc.name} with args: {tool_args}")

            try:
                # --- Tool Execution ---
                tool_result = tool_function(**tool_args)

                # --- Handle GCS URL from generate_report ---
                if fc.name == "generate_report" or fc.name == "application_report":
                    # tool_result is now the signed URL string
                    public_url = str(tool_result)
                    markdown_link = f"[Click here to download your report]({public_url})"
                    tool_result_for_ai = {
                        "status": "Success",
                        "markdown_link": markdown_link,
                        "message": f"Report generated. The link expires in 5 minutes."
                    }

                elif not isinstance(tool_result, (str, int, float, list, dict)):
                    tool_result_for_ai = str(tool_result)
                else:
                    tool_result_for_ai = tool_result

                result_json = json.dumps(tool_result_for_ai, default=json_serial)

            except Exception as e:
                print(f"Tool {fc.name} failed: {e}")
                tool_result_for_ai = {"error": str(e)}
                result_json = json.dumps(tool_result_for_ai, default=json_serial)

            # --- Rich Audit Logging (Tool Call) ---
            background_tasks.add_task(
                log_audit_event_to_bq,
                conversation_id=conversation_id,
                tool_name=fc.name,
                tool_args=tool_args,
                tool_response=result_json
            )

            function_response_content = {
                "function_response": {
                    "name": fc.name,
                    "response": {
                        "result": result_json
                    }
                }
            }

            response = chat_session.send_message(
                function_response_content,
                generation_config=gen_config
            )
            fc = get_function_call(response)

        # --- End of while loop (no more tool calls) ---
        try:
            content = response.text
        except ValueError as e:
            print(f"Response was blocked or empty: {e}")
            content = f"My response was blocked. (Error: {e})"

        # --- Rich Audit Logging (Final Response) ---
        background_tasks.add_task(
            log_audit_event_to_bq,
            conversation_id=conversation_id,
            final_response=content
        )

        resp = ChatResponse(
            id=f"chatcmpl_{created}",
            created=created,
            model=req.model or MODEL_NAME,
            choices=[Choice(index=0, message=Message(role="assistant", content=content))],
        )
        return resp

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error during chat generation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/models", response_model=ModelsResponse)
def list_models():
    import time
    return ModelsResponse(
        data=[ModelItem(id=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"), created=int(time.time()))]
    )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)