import sqlite3
import json
import httpx
from langchain_openai import ChatOpenAI
from langchain_core.messages.human import HumanMessage


# Initialize HTTP client
client = httpx.Client(verify=False)
DB_PATH = r"C:\Users\GENAIKOLGPUSR15\Desktop\Incident_management\incident_db\data\incident_iq.db"


# Initialize the LLM client
llm = ChatOpenAI(
    base_url="https://genailab.tcs.in",
    model="azure_ai/genailab-maas-DeepSeek-V3-0324",
    api_key="sk-vnedOvmLAuyelJh-X1G-tA",  # Provided for hackathon use only, do not misuse
    http_client=client
)


def get_incidents():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, payload_id, environment, severity_id, matched_pattern, payload, corrective_action
        FROM classifier_outputs
    
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def build_prompt(record):
    (
        incident_id,
        payload_id,
        environment,
        severity_id,
        matched_pattern,
        payload_json,
        corrective_action
    ) = record

    prompt = (
        f"Incident ID: {incident_id}\n"
        f"Payload ID: {payload_id}\n"
        f"Severity Level: {severity_id}\n"
        f"Environment: {environment}\n"
        f"Matched Pattern: {matched_pattern}\n"
        "Incident Details:\n" + (payload_json or "") + "\n"
        "Please provide detailed, actionable corrective steps for this incident."
    )
    return prompt


def main():
    incidents = get_incidents()
    if not incidents:
        print("No incident records found in database.")
        return

    print(f"Found {len(incidents)} incidents in the database.")

    for record in incidents:
        prompt = build_prompt(record)
        try:
            response = llm.invoke([HumanMessage(content=prompt)])
            corrective_action = response.content
            print(f"Corrective action for incident {record[0]} (Payload ID: {record[1]}):\n{corrective_action}\n{'-'*60}\n")
        except Exception as e:
            print(f"Error processing incident {record[0]}: {e}")


if __name__ == "__main__":
    main()
