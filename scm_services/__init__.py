from .cloner import Cloner


def bitbucketdc_service_factory(moniker, session, shared_secret, cloner):
    """
    A factory method that creates a service for use with Bitbucket Data Center.
    """
    from . import bbdc
    return bbdc.BitBucketDataCenterService(moniker, session, shared_secret, cloner)


def adoe_service_factory(moniker, session, shared_secret, cloner):
    """
    A factory method that creates a service for use with Azure DevOps Enterprise.
    """
    from . import ado
    return ado.ADOEnterpriseService(moniker, session, shared_secret, cloner)


