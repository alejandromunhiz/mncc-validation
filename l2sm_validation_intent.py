#!/usr/bin/env python3
"""
Publica un intent L2SM_NETWORK real via RabbitMQ para la red
'mncc-l2sm-validation' y espera/correlaciona la respuesta de mNCC/IBS.
Sigue exactamente el esquema usado en run_test_plan.py (_build_l2sm_network_intent,
_publish_intent_to_rabbitmq, _wait_for_mncc_response).
"""
import json
import time
import uuid
import sys

import pika

RMQ_HOST = "127.0.0.1"
RMQ_PORT = 5672
RMQ_USER = "nemo-user"
RMQ_PASS = "PRE4utv0ytf0fnbeuv"

INTENT_EXCHANGE = "nemo.api.workload"
INTENT_ROUTING_KEY = "intent-notify"

RESPONSE_EXCHANGE = "mncc"
RESPONSE_ROUTING_KEY = "mncc.ibs"

PROVIDER_NAME = "default-slice"
DOMAIN = "api.main.nemo.onelab.eu"

NETWORK_NAME = "mncc-l2sm-validation"

workload_id = str(uuid.uuid4())
intent_id = f"mncc_l2sm_validation_{workload_id}"

print(f"[INFO] workload_id = {workload_id}", file=sys.stderr)
print(f"[INFO] intent_id   = {intent_id}", file=sys.stderr)

intent_msg = {
    "userLabel": "cloud_continuum",
    "Intent": {
        "id": intent_id,
        "userLabel": "cloud_continuum",
        "intentExpectations": [
            {
                "expectationId": "1",
                "expectationVerb": "DELIVER",
                "expectationObject": {
                    "objectType": "L2SM_NETWORK",
                    "objectInstance": NETWORK_NAME,
                    "objectContexts": [
                        {
                            "contextAttribute": "name",
                            "contextCondition": "IS_EQUAL_TO",
                            "contextValueRange": NETWORK_NAME,
                        },
                        {
                            "contextAttribute": "providerName",
                            "contextCondition": "IS_EQUAL_TO",
                            "contextValueRange": PROVIDER_NAME,
                        },
                        {
                            "contextAttribute": "domain",
                            "contextCondition": "IS_EQUAL_TO",
                            "contextValueRange": DOMAIN,
                        },
                    ],
                },
                "expectationTargets": [
                    {
                        "targetName": "secure",
                        "targetCondition": "IS_EQUAL_TO",
                        "targetValueRange": "true",
                    }
                ],
            }
        ],
        "intentContexts": [
            {
                "contextAttribute": "NEMO_WORKLOAD",
                "contextCondition": "IS_EQUAL_TO",
                "contextValueRange": workload_id,
            }
        ],
        "intentPriority": 1,
        "observationPeriod": 60,
        "intentAdminState": "ACTIVATED",
    },
}

credentials = pika.PlainCredentials(RMQ_USER, RMQ_PASS)
conn_params = pika.ConnectionParameters(
    host=RMQ_HOST, port=RMQ_PORT, credentials=credentials,
    connection_attempts=3, retry_delay=2,
)

# 1) Set up response listener FIRST (avoid race: IBS responds fast)
resp_connection = pika.BlockingConnection(conn_params)
resp_channel = resp_connection.channel()
try:
    resp_channel.exchange_declare(exchange=RESPONSE_EXCHANGE, exchange_type="topic", passive=True)
except Exception:
    resp_connection = pika.BlockingConnection(conn_params)
    resp_channel = resp_connection.channel()
    resp_channel.exchange_declare(exchange=RESPONSE_EXCHANGE, exchange_type="topic", durable=True)

result = resp_channel.queue_declare(queue="", exclusive=True)
tmp_queue = result.method.queue
resp_channel.queue_bind(queue=tmp_queue, exchange=RESPONSE_EXCHANGE, routing_key=RESPONSE_ROUTING_KEY)

# 2) Publish the intent
pub_connection = pika.BlockingConnection(conn_params)
pub_channel = pub_connection.channel()
pub_channel.basic_publish(
    exchange=INTENT_EXCHANGE,
    routing_key=INTENT_ROUTING_KEY,
    body=json.dumps(intent_msg).encode("utf-8"),
    properties=pika.BasicProperties(content_type="application/json", delivery_mode=2),
)
pub_connection.close()
print(f"[INFO] Intent publicado en exchange={INTENT_EXCHANGE} routing_key={INTENT_ROUTING_KEY}", file=sys.stderr)
print(json.dumps(intent_msg, indent=2))

# 3) Collect ALL responses seen within timeout, correlate by workload_id / intent_id / network name
timeout = 60.0
all_responses = []
correlated = None

def on_response(ch, method, properties, body):
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        payload = {"_raw": body.decode("utf-8", errors="replace")}
    all_responses.append(payload)

resp_channel.basic_consume(queue=tmp_queue, on_message_callback=on_response, auto_ack=True)

start = time.time()
while (time.time() - start) < timeout:
    resp_connection.process_data_events(time_limit=1)
    # Try to find correlation early, but keep draining a bit to capture all
    for r in all_responses:
        blob = json.dumps(r)
        if workload_id in blob or intent_id in blob or NETWORK_NAME in blob:
            correlated = r
    if correlated and (time.time() - start) > 5:
        break

resp_connection.close()

print(f"\n[INFO] Total respuestas recibidas en mncc.ibs durante la ventana: {len(all_responses)}", file=sys.stderr)
print("=== ALL_RESPONSES_JSON ===")
print(json.dumps(all_responses, indent=2))
print("=== CORRELATED_RESPONSE_JSON ===")
print(json.dumps(correlated, indent=2))

# Write correlation marker to stderr for shell scripting
if correlated:
    print(f"[RESULT] CORRELATED=YES workload_id={workload_id} intent_id={intent_id} network={NETWORK_NAME}", file=sys.stderr)
else:
    print(f"[RESULT] CORRELATED=NO workload_id={workload_id} intent_id={intent_id} network={NETWORK_NAME}", file=sys.stderr)
