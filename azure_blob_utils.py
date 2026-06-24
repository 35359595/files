"""
Azure Blob upload helper for the IB telemetry collector.

Authentication preference:
1. Explicit account_key in config or AZURE_STORAGE_KEY.
2. Explicit client secret in config.
3. DefaultAzureCredential, which covers AZURE_TENANT_ID/AZURE_CLIENT_ID/
   AZURE_CLIENT_SECRET, managed identity, and local Azure CLI login.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.core.credentials import AzureNamedKeyCredential

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _cfg(config: Dict[str, Any], key: str, env: Optional[str] = None) -> Optional[str]:
    value = config.get(key)
    if value is None or str(value).strip() == "":
        value = os.environ.get(env or key.upper())
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _object_key(prefix: Optional[str], filename: str) -> str:
    clean_prefix = (prefix or "").strip().strip("/")
    return f"{clean_prefix}/{filename}" if clean_prefix else filename


def create_blob_service_client(config: Dict[str, Any]) -> Optional[BlobServiceClient]:
    account_name = _cfg(config, "account_name", "AZURE_STORAGE_ACCOUNT")
    account_url = _cfg(config, "account_url", "AZURE_STORAGE_ACCOUNT_URL")
    account_key = _cfg(config, "account_key", "AZURE_STORAGE_KEY")

    if not account_url:
        if not account_name:
            logger.error("Azure Blob account_name or account_url is required.")
            return None
        account_url = f"https://{account_name}.blob.core.windows.net"

    try:
        if account_key:
            if not account_name:
                account_name = account_url.split("//", 1)[-1].split(".", 1)[0]
            credential = AzureNamedKeyCredential(account_name, account_key)
        else:
            tenant_id = _cfg(config, "tenant_id", "AZURE_TENANT_ID")
            client_id = _cfg(config, "client_id", "AZURE_CLIENT_ID")
            client_secret = _cfg(config, "client_secret", "AZURE_CLIENT_SECRET")
            if tenant_id and client_id and client_secret:
                credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            else:
                credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)

        return BlobServiceClient(account_url=account_url, credential=credential)
    except Exception as exc:
        logger.error("Failed to create Azure Blob client: %s", exc)
        return None


def upload_file_to_azure_blob(
    blob_service_client: BlobServiceClient,
    file_path: str | os.PathLike[str],
    container_name: str,
    upload_folder_path: Optional[str] = None,
) -> Dict[str, Any]:
    if blob_service_client is None:
        return {"status": "error", "reason": "blob_service_client cannot be None."}

    if not container_name or not container_name.strip():
        return {"status": "error", "reason": "container_name cannot be empty."}

    path = Path(file_path)
    if not path.exists():
        return {"status": "error", "reason": f"File does not exist: {path}"}
    if not path.is_file():
        return {"status": "error", "reason": f"Path is not a file: {path}"}
    if not os.access(path, os.R_OK):
        return {"status": "error", "reason": f"File is not readable: {path}"}

    object_key = _object_key(upload_folder_path, path.name)

    try:
        container_client = blob_service_client.get_container_client(container_name)
        if not container_client.exists():
            return {"status": "error", "reason": f"Container does not exist or is not accessible: {container_name}"}

        blob_client = container_client.get_blob_client(object_key)
        with path.open("rb") as handle:
            blob_client.upload_blob(handle, overwrite=True)

        return {
            "status": "success",
            "container": container_name,
            "key": object_key,
            "file_path": str(path),
            "url": blob_client.url,
        }
    except ResourceNotFoundError as exc:
        return {"status": "error", "reason": f"Container or blob path was not found: {exc}"}
    except AzureError as exc:
        return {"status": "error", "reason": f"Azure Blob upload failed: {exc}"}
    except Exception as exc:
        logger.exception("Unexpected error during Azure Blob upload")
        return {"status": "error", "reason": f"Unexpected error during Azure Blob upload: {exc}"}
