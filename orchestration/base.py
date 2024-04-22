
class OrchestratorBase:

    def __init__(self, headers, webhook_payload):
        self.__webhook_payload = webhook_payload
        self.__headers = headers

    @property
    def _headers(self):
        return self.__headers

    @property
    def route_urls(self):
        raise NotImplementedError("route_urls")

    @property
    def _webhook_payload(self):
        return self.__webhook_payload
    
    def is_signature_valid(self, shared_secret):
        raise NotImplementedError("is_signature_valid")

