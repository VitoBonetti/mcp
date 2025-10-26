from google.cloud import secretmanager
from google.oauth2 import service_account
import os

def get_secret(project_id: str, secret_id: str, version: str = "latest") -> str:
    # Use SA key if present; otherwise default ADC on GCE
    key_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if key_path and os.path.exists(key_path):
        creds = service_account.Credentials.from_service_account_file(key_path)
        client = secretmanager.SecretManagerServiceClient(credentials=creds)
    else:
        client = secretmanager.SecretManagerServiceClient()

    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")
