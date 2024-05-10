from .cloner import Cloner
from .scm import SCMService

def bitbucketdc_cloner_factory(username=None, password=None, token=None, ssh_path=None):
        
    if username is not None and password is not None:
            return Cloner.using_basic_auth(username, password) 
    
    if token is not None:
            return Cloner.using_token_auth(token, username)
    
    if ssh_path is not None:
            return Cloner.using_ssh_auth(ssh_path)

    return None        

def adoe_cloner_factory(username=None, password=None, token=None, ssh_path=None):
    if username is not None and password is not None:
            return Cloner.using_url_creds(username, password) 
    
    if token is not None:
            return Cloner.using_basic_auth("", token)
    
    if ssh_path is not None:
            return Cloner.using_ssh_auth(ssh_path)
