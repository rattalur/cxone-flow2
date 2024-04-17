

def bitbucketdc_service_factory(session):
    """
    A factory method that creates a service for use with Bitbucket Data Center.
    """
    from . import bbdc
    return bbdc.BitBucketDataCenterService(session)

