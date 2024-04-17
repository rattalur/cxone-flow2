
from instance import CxOneInstance

class CxOneFlowConfig:

    @staticmethod
    def init(file_path = None):
        pass

    # With no args: Gets a list of CxOneFlowConfig objects, each standing for a single environment
    # webhook_src_url: Gets the first environment that has an SCM that matches the source url
    def environments(self, webhook_src_url=None):
        pass

