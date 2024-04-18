from _version import __version__
from pathlib import Path
import yaml, logging, cxone_api as cx, os
from scm_services import bitbucketdc_service_factory
from api_utils import auth_bearer, auth_basic, APISession

from password_strength import PasswordPolicy

class ConfigurationException(Exception):

    @staticmethod
    def missing_key_path(key_path):
        return ConfigurationException(f"Missing key at path: {key_path}")

    @staticmethod
    def invalid_value (key_path):
        return ConfigurationException(f"The value configured at {key_path} is invalid")

    @staticmethod
    def missing_keys(key_path, keys):
        return ConfigurationException(f"One or more of these elements are missing: {["/".join([key_path, x]) for x in keys]}")

    @staticmethod
    def missing_at_least_one_key_path(key_path, keys):
        return ConfigurationException(f"At least one of these elements is required: {["/".join([key_path, x]) for x in keys]}")

    @staticmethod
    def mutually_exclusive(key_path, keys):
        return ConfigurationException(f"Only one of these keys should be defined: {["/".join([key_path, x]) for x in keys]}")



class CxOneFlowConfig:

    __log = logging.getLogger("CxOneFlowConfig")

    __secret_policy = PasswordPolicy.from_names(length=20, uppercase=3, numbers=3, special=2)


    @staticmethod
    def bootstrap(config_file_path = "./config.yaml"):

        CxOneFlowConfig.__log.info(f"Loading configuration from {config_file_path}")

        with open(config_file_path, "rt") as cfg:
            CxOneFlowConfig.__raw = yaml.safe_load(cfg)

        if not "secret-root-path" in CxOneFlowConfig.__raw.keys():
            raise ConfigurationException.missing_key_path("/secret-root-path")
        else:
            CxOneFlowConfig.__secret_root = CxOneFlowConfig.__raw['secret-root-path']

        if len(CxOneFlowConfig.__raw.keys() - CxOneFlowConfig.__scm_service_factories.keys()) == len(CxOneFlowConfig.__raw.keys()):
            raise ConfigurationException.missing_at_least_one_key_path("/", CxOneFlowConfig.__scm_service_factories,keys())
        
        for scm in CxOneFlowConfig.__scm_service_factories.keys():

            # SCM:
            # only token or username/password
            # api-auth is used for clone-auth if clone-auth is not provided.
            # shared secret - do length and strength requirements.

            if scm in CxOneFlowConfig.__raw.keys():
                index = 0
                for repo_config_dict in CxOneFlowConfig.__raw[scm]:
                    CxOneFlowConfig.__setup_scm(CxOneFlowConfig.__scm_service_factories[scm], repo_config_dict, f"/{scm}[{index}]")
                    index += 1

    @staticmethod
    def __get_value_for_key_or_fail(config_path, key, config_dict):
        if not key in config_dict.keys():
            raise ConfigurationException.missing_key_path(f"{config_path}/{key}")
        else:
            return config_dict[key]

    @staticmethod
    def __get_secret_from_value_of_key_or_fail(config_path, key, config_dict):
        if not key in config_dict.keys():
            raise ConfigurationException.missing_key_path(f"{config_path}/{key}")
        else:
            if not os.path.isfile(config_dict[key]):
                raise ConfigurationException.invalid_value(f"{config_path}/{key}")
            else:
                with open(Path(CxOneFlowConfig.__secret_root) / Path(config_dict[key]), "rt") as secret:
                    return secret.readline().strip()

    @staticmethod
    def __get_value_for_key_or_default(key, config_dict, default):
        if not key in config_dict.keys():
            return default
        else:
            return config_dict[key]

    @staticmethod
    def __cxone_client_factory(config_path, **kwargs):

        always_required = ['tenant', 'iam-endpoint', 'api-endpoint']

        if len(always_required - kwargs.keys()) != 0:
            raise ConfigurationException.missing_keys(config_path, always_required)

        one_required = ['api-key','oauth']
        one_found = len([x for x in one_required if x in kwargs.keys()])

        if one_found != 1:
            raise ConfigurationException.mutually_exclusive(config_path, one_required)
        

        tenant_name = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'tenant', kwargs)

        iam_endpoint_value = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'iam-endpoint', kwargs)
        tenant_auth_endpoint = None
        if iam_endpoint_value in cx.AuthRegionEndpoints.keys():
            tenant_auth_endpoint = cx.AuthRegionEndpoints[iam_endpoint_value]
        else:
            tenant_auth_endpoint = cx.CxOneAuthEndpoint(tenant_name, iam_endpoint_value)


        api_endpoint_value = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'api-endpoint', kwargs)
        tenant_api_endpoint = None
        if api_endpoint_value in cx.ApiRegionEndpoints.keys():
            tenant_api_endpoint = cx.ApiRegionEndpoints[api_endpoint_value]
        else:
            tenant_api_endpoint = cx.CxOneApiEndpoint(api_endpoint_value)

        if 'api-key' in kwargs.keys():
            return cx.CxOneClient.create_with_api_key(
                CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(config_path, 'api-key', kwargs), \
                __name__, __version__, \
                tenant_auth_endpoint, \
                tenant_api_endpoint, \
                CxOneFlowConfig.__get_value_for_key_or_default('timeout-seconds', 60), \
                CxOneFlowConfig.__get_value_for_key_or_default('retries', 3), \
                CxOneFlowConfig.__get_value_for_key_or_default('proxies', None), \
                CxOneFlowConfig.__get_value_for_key_or_default('ssl-verify', True) \
                )
        elif 'oauth' in kwargs.keys():
            oauth_params = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'oauth', kwargs)
            oauth_id = CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(f"{config_path}/oauth", 'client-id', oauth_params)
            oauth_secret = CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(f"{config_path}/oauth", 'client-secret', oauth_params)

            return cx.CxOneClient.create_with_oauth(
                oauth_id, oauth_secret, \
                __name__, __version__, \
                tenant_auth_endpoint, \
                tenant_api_endpoint, \
                CxOneFlowConfig.__get_value_for_key_or_default('timeout-seconds', 60), \
                CxOneFlowConfig.__get_value_for_key_or_default('retries', 3), \
                CxOneFlowConfig.__get_value_for_key_or_default('proxies', None), \
                CxOneFlowConfig.__get_value_for_key_or_default('ssl-verify', True) \
                )

        return None

    @staticmethod
    def __setup_scm(service_factory, config_dict, config_path):
        repo_match_spec = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'repo-match', config_dict)
        scan_config_dict = CxOneFlowConfig.__get_value_for_key_or_default('scan-config', config_dict, {} )
            # update-project-clone-creds
            # default-scan-engines - convert to payload as it would exist in the POST
            # default-scan-tags - convert for POST
            # default-project-tags - convert for POST
        connection = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'connection', config_dict)
            # base-url - required
            # shared-secret - required
            # timeout-seconds - optional default 60
            # retries - optional default 3
            # ssl-verify - optional default True
            # proxies - optional default None
            # api-auth - required.  At least one of the following is defined:
                # token
                # ssh
                # username/password
            # clone-auth - optional default: api-auth
                # token
                # ssh
                # username/password

        cxone_client = CxOneFlowConfig.__cxone_client_factory(f"{config_path}/cxone", 
                                                            **(CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'cxone', config_dict)))

        pass
        
    __scm_service_factories = {'bbdc' : bitbucketdc_service_factory }

        

        


