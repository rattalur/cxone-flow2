"""
This is a Flask entrypoint for receiving webhook payloads and dispatching them to the proper
orchestrator.  Code here should be limited to receive and delegating the logic to the
proper orchestrator.  This allows this to be replaced with a different type of endpoint handler
that is compatible with other methods of deployment.
"""
from _version import __version__
from flask import Flask, request, Response
from orchestration import OrchestrationDispatch, BitBucketDataCenterOrchestrator
import json, logging
from config import CxOneFlowConfig
from status import Status
from time import perf_counter_ns

__app_name__ = f"cxone-flow/{__version__}"

__log = logging.getLogger(__app_name__)

Status.bootstrap()
CxOneFlowConfig.bootstrap()

app = Flask(__app_name__)


@app.get("/status")
async def node_status():
    return Response(json.dumps(await Status.get()), status=200)

@app.post("/bbdc")
async def bbdc_webhook_endpoint():
    counter = perf_counter_ns()
    __log.info("Received hook for BitBucket Data Center")
    __log.debug(f"bbdc webhook: headers: [{request.headers}] body: [{json.dumps(request.json)}]")
    try:
        resp = Response(status=await OrchestrationDispatch.execute(BitBucketDataCenterOrchestrator(request.headers, request.data)))
        await Status.report("wsgi", "bbdc", perf_counter_ns() - counter)
        return resp
    except Exception as ex:
        await Status.report("wsgi-error", "bbdc", perf_counter_ns() - counter)
        __log.error(ex)
        return Response(status=400)



