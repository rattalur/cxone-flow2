from .base import OrchestratorBase
import json

class BitBucketDataCenterOrchestrator(OrchestratorBase):

    def __init__(self, headers, webhook_payload):
        OrchestratorBase.__init__(self, headers, webhook_payload)
        self.__json = json.loads(webhook_payload)

        self.__route_urls = None

        if "repository" in self.__json.keys():
            if "links" in self.__json['repository'].keys():
                if "clone" in self.__json['repository']['links'].keys():
                    self.__route_urls = []
                    for d in self.__json['repository']['links']['clone']:
                        if "href" in d.keys():
                            self.__route_urls.append(d['href'])

    @property
    def route_urls(self):
        return self.__route_urls

    def is_signature_valid(self, shared_secret):
        # X-Hub-Signature
        raise NotImplementedError("is_signature_valid")
    

    # @staticmethod
    # async def execute(cxone_service, scm_service, headers, raw_payload):
    #     return 204
