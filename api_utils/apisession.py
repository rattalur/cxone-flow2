from _version import __version__
from _agent import __agent__
from requests import Session


class APISession(Session):
    def __init__(self, api_base_endpoint, auth, timeout=60, retries=3, proxies=None, ssl_verify=True):
        Session.__init__(self)

        self.headers = { "User-Agent" : __agent__ }
        
        self.__base_endpoint = api_base_endpoint
        self.__timeout = timeout
        self.__retries = retries

        self.verify = ssl_verify
        self.proxies = proxies
        self.auth = auth

    @property
    def base_endpoint(self):
        return self.__base_endpoint

    @property
    def timeout(self):
        return self.__timeout

    @property
    def retries(self):
        return self.__retries




