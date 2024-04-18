from .bbdc import BitBucketDataCenterOrchestrator
from api_utils import verify_signature
import logging

class OrchestrationDispatch:

    __log = logging.getLogger("OrchestrationDispatch")

    @staticmethod
    async def execute(orchestrator, signature_value, headers_func, json_payload_func, raw_payload_func):

        # TODO: SECRET AS A CONFIG ELEMENT
        if verify_signature(signature_value, "password", raw_payload_func()):
            OrchestrationDispatch.__log.debug("Payload signature verified.")
        else:
            OrchestrationDispatch.__log.error("Signature validation failure, rejecting webhook request.")
            return 403

        return orchestrator.execute(None, headers_func(), json_payload_func())



class ScanOrchestration:
    """
    Uses an SCMService instance and a CxOneClient instance to orchestrate scanning
    """
    pass


class TagOrchestration:
    """
    Given parameters that were used to tag scans and a CxOneClient instance, orchestrates
    tagging of scans.
    """
    pass