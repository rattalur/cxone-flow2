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



__app_name__ = f"cxone-flow/{__version__}"

__log = logging.getLogger(__app_name__)

CxOneFlowConfig.bootstrap()

app = Flask(__app_name__)



@app.get("/ping")
def ping():
    return Response("pong")

@app.post("/bbdc")
async def bbdc_webhook_endpoint():
    __log.info("Received hook for BitBucket Data Center")
    __log.debug(f"bbdc webhook: headers: [{request.headers}] body: [{json.dumps(request.json)}]")
    try:
        return Response(status=await OrchestrationDispatch.execute(BitBucketDataCenterOrchestrator(request.headers, request.data)))
    except Exception as ex:
        __log.error(ex)
        return Response(status=400)



