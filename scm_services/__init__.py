from .cloner import Cloner
from .scm import SCMService

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
