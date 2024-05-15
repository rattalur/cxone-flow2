from .cloner import Cloner
from .scm import SCMService
from api_utils import auth_basic, auth_bearer


def bitbucketdc_cloner_factory(username=None, password=None, token=None, ssh_path=None, ssh_port=None):
        if username is not None and password is not None:
                return Cloner.using_basic_auth(username, password) 

        if token is not None:
                return Cloner.using_token_auth(token, username)

        if ssh_path is not None:
                return Cloner.using_ssh_auth(ssh_path, ssh_port)

        return None        

def adoe_cloner_factory(username=None, password=None, token=None, ssh_path=None, ssh_port=None):
        if username is not None and password is not None:
                return Cloner.using_basic_auth(username, password) 

        if token is not None:
                return Cloner.using_basic_auth("", token, True)

        if ssh_path is not None:
                return Cloner.using_ssh_auth(ssh_path, ssh_port)


def adoe_api_auth_factory(username=None, password=None, token=None):
        if token is not None:
                return auth_basic("", token)
        else:
                return auth_basic(username, password)


def bbdc_api_auth_factory(username=None, password=None, token=None):
        if token is not None:
                return auth_bearer(token)
        else:
                return auth_basic(username, password)
