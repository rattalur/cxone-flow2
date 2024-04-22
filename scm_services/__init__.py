

def bitbucketdc_service_factory(session, shared_secret, cloner):
    """
    A factory method that creates a service for use with Bitbucket Data Center.
    """
    from . import bbdc
    return bbdc.BitBucketDataCenterService(session, shared_secret, cloner)



class Cloner:

    __use_ssh = False
    
    @staticmethod
    def using_basic_auth(username, password):
        pass

    @staticmethod
    def using_token_auth(token):
        pass

    @staticmethod
    def using_ssh_auth(ssh_private_key):
        Cloner.__use_ssh = True
        pass

    def clone(self, clone_url):
        pass

    class __clone_worker:
        def __init__(self, clone_url):
            pass

        def __aenter__(self):
            pass

        def __aexit__(self):
            pass

        def __repr__(self) -> str:
            pass



