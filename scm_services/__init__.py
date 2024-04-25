from .cloner import Cloner

def bitbucketdc_service_factory(moniker, session, shared_secret, cloner):
    """
    A factory method that creates a service for use with Bitbucket Data Center.
    """
    from . import bbdc
    return bbdc.BitBucketDataCenterService(moniker, session, shared_secret, cloner)



