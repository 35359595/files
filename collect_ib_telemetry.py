import argparse
import os
import json
import shutil
import socket
import time
import logging
from logging.handlers import RotatingFileHandler
from multiprocessing import Pool

import pandas as pd
import paramiko
from paramiko.ssh_exception import NoValidConnectionsError, SSHException, AuthenticationException

from azure_blob_utils import create_blob_service_client, upload_file_to_azure_blob

# ============================================================
# Paths (relative)
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
RAW_OUTPUT_DIR = os.path.join(OUTPUT_DIR, "raw")
FINAL_OUTPUT_DIR = os.path.join(OUTPUT_DIR, "final")

FAILURE_FILE = os.path.join(SCRIPT_DIR, "failures.txt")

# Log directory + file
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "telemetry_automation.log")

# ============================================================
# Logging setup
# A single logger call writes to BOTH the console AND the log file.
# Used ONLY at mandatory failure points; normal flow uses print().
#   RotatingFileHandler -> 5MB per file, keep 5 backups (~30MB cap)
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%m-%d-%Y %H:%M:%S",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=5),
        logging.StreamHandler(),
    ],
)
# Keep paramiko quiet, but let our own logs through
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# CSV columns required for processing
REQUIRED_COLUMNS = ["ServerAddress", "DeviceConfig", "ClusterName", "LinkType"]

# ============================================================
# Commands
# ============================================================
IB_COMMAND_SEQUENCE = ["enable", "config t", "fae iblinkinfo -l -t 50", "exit", "exit"]
UFM_3_0_COMMAND = "iblinkinfo -l -t 50"
XDR_SWITCH_COMMAND = "sudo iblinkinfo -l -t 50"


# ============================================================
# Helpers
# ============================================================
def local_timestamp():
    """Return local time as 'mm-dd-YYYY HH:MM:SS TZ', e.g. '06-18-2026 20:50:02 PDT'."""
    return time.strftime("%m-%d-%Y %H:%M:%S %Z", time.localtime())


def get_output_file_name():
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    return os.path.join(FINAL_OUTPUT_DIR, f"IBLINKINFO_{timestamp}.txt")


def prepare_directories():
    shutil.rmtree(RAW_OUTPUT_DIR, ignore_errors=True)
    os.makedirs(RAW_OUTPUT_DIR, exist_ok=True)
    os.makedirs(FINAL_OUTPUT_DIR, exist_ok=True)


def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError("config.json not found")

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    if not config.get("credentials"):
        raise ValueError("Missing device credentials in config.json")

    if not config.get("Azure_blob"):
        raise ValueError("Missing Azure_blob configuration in config.json")

    return config


def sanitize_filename(value):
    if not value:
        return "unknown"
    invalid = ['\\', '/', ':', '*', '?', '"', '<', '>', '|', ' ']
    for c in invalid:
        value = str(value).replace(c, "_")
    return value


def wrap_cluster_output(cluster_name, link_type, content):
    return f"#{cluster_name}-{link_type}\n{content}\nend\n"


def get_device_type(device_config):
    device_type = str(device_config).lower()
    if "3.0" in device_type or "3.5" in device_type:
        return "UFM3"
    elif "ib" in device_type:
        return "IB"
    return "UNKNOWN"


def write_footer(start_time, alert=None):
    """Write the run footer (end time + duration) to the failure log. DRY helper."""
    end_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    duration = time.time() - start_time
    duration_min = int(duration // 60)
    duration_sec = int(duration % 60)

    with open(FAILURE_FILE, "a") as f:
        if alert:
            f.write(f"{alert}\n")
        f.write("-" * 120 + "\n")
        f.write(
            f"Automation End Time: {end_str} , "
            f"Duration: {duration_min} minutes and {duration_sec} seconds\n"
        )
        f.write("-" * 120 + "\n")


# ============================================================
# SSH CLASS
# ============================================================
class SSHConnection:
    def __init__(self, host, username, password):
        self.host = host
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.username = username
        self.password = password

    def connect(self):
        self.client.connect(
            self.host,
            22,
            self.username,
            self.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=60,
        )

    def execute_shell_commands(self, commands):
        channel = self.client.invoke_shell()
        time.sleep(5)

        for cmd in commands:
            channel.send(cmd + "\n")
            time.sleep(2)

        output = ""
        last = time.time()

        while time.time() - last < 10:
            if channel.recv_ready():
                output += channel.recv(65535).decode(errors="ignore")
                last = time.time()
            else:
                time.sleep(1)

        return output

    def execute_single_command(self, command):
        stdin, stdout, stderr = self.client.exec_command(command, get_pty=True)
        time.sleep(5)

        output = stdout.read().decode(errors="ignore")
        error = stderr.read().decode(errors="ignore")

        if error:
            output += "\n" + error

        return output

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass


# ============================================================
# PROCESS SERVER
# ============================================================
def process_server(args):
    # Suppress paramiko logs in worker processes too (cross-platform safety)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("paramiko.transport").setLevel(logging.WARNING)

    row, credentials = args
    server, device_config, cluster, link_type = row

    device_type = get_device_type(device_config)

    if device_type == "UNKNOWN":
        return {"status": "failure", "Device": server, "cluster": cluster,
                "reason": "Configuration not recognized"}

    creds = credentials.get(device_type, [])

    for cred in creds:
        ssh = SSHConnection(server, cred["username"], cred["password"])

        try:
            ssh.connect()

            if device_type == "UFM3":
                output = ssh.execute_single_command(UFM_3_0_COMMAND)

            elif device_type == "IB" and str(link_type).upper() == "XDR":
                output = ssh.execute_single_command(XDR_SWITCH_COMMAND)

            else:
                output = ssh.execute_shell_commands(IB_COMMAND_SEQUENCE)

            if output and len(output.splitlines()) > 120:
                file_path = os.path.join(
                    RAW_OUTPUT_DIR,
                    f"{sanitize_filename(cluster)}_{sanitize_filename(server)}_{int(time.time())}.txt",
                )

                with open(file_path, "w") as f:
                    f.write(wrap_cluster_output(cluster, str(link_type).upper(), output))

                return {"status": "success", "file": file_path}
            else:
                return {"status": "failure", "Device": server, "cluster": cluster,
                        "reason": "Device Authorizable but data error"}

        except AuthenticationException:
            continue
        except (NoValidConnectionsError, socket.gaierror, ConnectionRefusedError):
            return {"status": "failure", "Device": server, "cluster": cluster,
                    "reason": "Device Unaccessible"}
        except (TimeoutError, socket.timeout, SSHException):
            return {"status": "failure", "Device": server, "cluster": cluster,
                    "reason": "Device not Responding"}
        except Exception as e:
            return {"status": "failure", "Device": server, "cluster": cluster,
                    "reason": f"Unknown failure : {str(e)}"}
        finally:
            ssh.close()

    return {"status": "failure", "Device": server, "cluster": cluster,
            "reason": "Provided credentials not working"}


# ============================================================
# MERGE
# ============================================================
def combine_output_files(files):
    final_file = get_output_file_name()

    with open(final_file, "w") as out:
        for f in files:
            with open(f) as fi:
                out.write(fi.read() + "\n")

    return final_file


# ============================================================
# MAIN
# ============================================================
def main(csv):
    start_time = time.time()
    start_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    prepare_directories()
    config = load_config()
    credentials = config["credentials"]
    azure_blob = config["Azure_blob"]

    df = pd.read_csv(csv)

    # Validate required columns up front
    missing = set(REQUIRED_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"CSV missing required columns: {missing}")

    rows = df[REQUIRED_COLUMNS].values.tolist()

    # Header append (human-readable per-device failure file)
    with open(FAILURE_FILE, "a") as f:
        f.write("\n" + "=" * 120 + "\n")
        f.write(f"Automation Start Time : {start_str}\n")
        f.write("=" * 120 + "\n")

    # Guard: empty CSV -> nothing to process
    if not rows:
        logger.error("[ALERT] CSV contains no rows. Nothing to process.")          # mandatory
        write_footer(start_time, alert="[ALERT] CSV contains no rows.")
        return

    process_count = min(config.get("process_count", 25), len(rows))

    # Stage 1: Telemetry collection
    print("[STAGE 1] Collecting telemetry data from devices...")
    with Pool(process_count) as pool:
        results = pool.map(process_server, [(r, credentials) for r in rows])

    success = [r["file"] for r in results if r["status"] == "success"]
    failure = [r for r in results if r["status"] == "failure"]

    # MANDATORY: persist each device failure to the log file (and console)
    for item in failure:
        logger.error("[DEVICE FAILURE] %s | %s | %s",
                     item["Device"], item["cluster"], item["reason"])

    # Keep human-readable per-device failure summary file
    with open(FAILURE_FILE, "a") as f:
        for item in failure:
            f.write(f"{item['Device']:<30} {item['cluster']:<35} ------ {item['reason']}\n")

    # Stage 2: Generate consolidated file (skip if nothing succeeded)
    if not success:
        print(f"Processed: {len(rows)} | Success: 0 | Failed: {len(failure)}")
        logger.error("[ALERT] No successful telemetry collected.")                 # mandatory
        write_footer(start_time, alert="[ALERT] Final output file has no data..")
        return

    final_output_file = combine_output_files(success)

    # Safety check: final file missing or empty
    if not os.path.exists(final_output_file) or os.path.getsize(final_output_file) == 0:
        print(f"Processed: {len(rows)} | Success: {len(success)} | Failed: {len(failure)}")
        logger.error("[ALERT] Final telemetry payload is empty.")                  # mandatory
        write_footer(start_time, alert="[ALERT] Final output file has no data..")
        return

    # Stage 2 line first, THEN the summary
    print(f"[STAGE 2] File generated: {os.path.basename(final_output_file)}")
    print(f"Processed: {len(rows)} | Success: {len(success)} | Failed: {len(failure)}")

    # Stage 3: Azure Blob upload
    print("[STAGE 3] Uploading file to Azure Blob...")
    client = create_blob_service_client(azure_blob)

    if not client:
        logger.error("[FAILURE] Could not create Azure Blob client. Local file retained.")  # mandatory
        write_footer(start_time, alert="[ALERT] Azure Blob client creation failed.")
        return

    container_name = azure_blob.get("container_name")
    upload_folder_path = azure_blob.get("upload_folder_path")
    result = upload_file_to_azure_blob(client, final_output_file, container_name, upload_folder_path)

    # Delete local file ONLY after a confirmed successful upload
    if result.get("status") == "success":
        print(f"[SUCCESS] Azure Blob upload completed -> {result['container']}/{result['key']}")
        if os.path.exists(final_output_file):
            os.remove(final_output_file)
    else:
        logger.error("[FAILURE] Azure Blob upload failed: %s", result.get("reason"))  # mandatory
        print("[INFO] Local file retained for retry.")

    # Footer
    write_footer(start_time)


# ============================================================
# ENTRY
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_filename")
    args = parser.parse_args()

    script_start = time.time()
    print(f"Program is started at {local_timestamp()}")
    try:
        main(args.csv_filename)
    except Exception as exc:
        logger.exception("Fatal error in automation run")   # mandatory: full traceback to file
        print(f"[FATAL] Automation aborted: {exc}")
        raise SystemExit(1)
    finally:
        duration = time.time() - script_start
        print(f"Program is ended at   {local_timestamp()}")
        print(f"Total execution time  : {int(duration // 60)}m {int(duration % 60)}s")