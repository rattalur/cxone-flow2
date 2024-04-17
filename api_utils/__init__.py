from .apisession import APISession
from requests.auth import AuthBase,HTTPBasicAuth
from .signatures import signature


def auth_basic(username, password):
    return HTTPBasicAuth(username, password)


def auth_bearer(token):
    class HTTPBearerAuth(AuthBase):
        def __init__(self, token):
            AuthBase.__init__(self)
            self.__token = token

        def __call__(self, r):
            r.headers["Authorization"] = f"Bearer {self.__token}"
            return r
    
    return HTTPBearerAuth(token)

def verify_signature(signature_header, secret, body):
    (algorithm, hash) = signature_header.split("=")

    generated_hash = signature.get(algorithm, secret, body)

    return generated_hash == hash


