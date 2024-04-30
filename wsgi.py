"""
This is a Flask entrypoint for receiving webhook payloads and dispatching them to the proper
orchestrator.  Code here should be limited to receive and delegating the logic to the
proper orchestrator.  This allows this to be replaced with a different type of endpoint handler
that is compatible with other methods of deployment.
"""
from _agent import __agent__
from flask import Flask, request, Response
from orchestration import OrchestrationDispatch, BitBucketDataCenterOrchestrator
import json, logging, asyncio
from config import CxOneFlowConfig
from status import Status
from time import perf_counter_ns
from task_management import TaskManager
import cxoneflow_logging as cof_logging

cof_logging.bootstrap()

__app_name__ = __agent__



__log = logging.getLogger(__app_name__)

Status.bootstrap()
CxOneFlowConfig.bootstrap()
TaskManager.bootstrap()


app = Flask(__app_name__)

@app.get("/ping")
async def ping():
    return Response("pong", status=200)


# Need an IPC mechanism for this, will revisit this later
# @app.get("/status")
# async def node_status():
#     return Response(json.dumps(await Status.get()), status=200)


@app.post("/bbdc")
async def bbdc_webhook_endpoint():
    counter = perf_counter_ns()
    __log.info("Received hook for BitBucket Data Center")
    __log.debug(f"bbdc webhook: headers: [{request.headers}] body: [{json.dumps(request.json)}]")
    try:
        TaskManager.in_background(OrchestrationDispatch.execute(BitBucketDataCenterOrchestrator(request.headers, request.data)))
        return Response(status=204)
    except Exception as ex:
        __log.error(ex)
        return Response(status=400)

  
