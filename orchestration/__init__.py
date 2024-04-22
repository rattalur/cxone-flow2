from api_utils import verify_signature
from .bbdc import BitBucketDataCenterOrchestrator
import logging
from config import CxOneFlowConfig

class OrchestrationDispatch:

    __log = logging.getLogger("OrchestrationDispatch")

    @staticmethod
    async def execute(orchestrator):

        OrchestrationDispatch.__log.debug(f"Service lookup: {orchestrator.route_urls}")

        cxone_service, scm_service = await CxOneFlowConfig.retrieve_services_by_route(orchestrator.route_urls)

        OrchestrationDispatch.__log.debug(f"Service lookup success: {orchestrator.route_urls}")

        # if verify_signature(signature_value, "password", raw_payload_func()):
        #     OrchestrationDispatch.__log.debug("Payload signature verified.")
        # else:
        #     OrchestrationDispatch.__log.error("Signature validation failure, rejecting webhook request.")
        #     return 403

        # return orchestrator.execute(None, None, headers, raw_payload)
        
        return 204



