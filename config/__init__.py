from _version import __version__
from _agent import __agent__
from pathlib import Path
import re
import yaml, logging, cxone_api as cx, os
from scm_services import Cloner, bitbucketdc_service_factory
from api_utils import auth_bearer, auth_basic, APISession
from cxone_service import CxOneService
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

    @staticmethod
    def invalid_keys(key_path, keys):
        return ConfigurationException(f"These keys are invalid: {["/".join([key_path, x]) for x in keys]}")

class RouteNotFoundException(Exception):
    pass

class CxOneFlowConfig:

    __log = logging.getLogger("CxOneFlowConfig")

    __shared_secret_policy = PasswordPolicy.from_names(length=20, uppercase=3, numbers=3, special=2)


    @staticmethod
    async def retrieve_services_by_route(clone_urls):

        if type(clone_urls) is list:
            it_list = clone_urls
        else:
            it_list = [clone_urls]

        for url in it_list:
            for entry in CxOneFlowConfig.__ordered_scm_config_tuples:
                if entry[0].match(url):
                    return entry[1], entry[2]

        CxOneFlowConfig.__log.error(f"No route matched for {clone_urls}")
        raise RouteNotFoundException(clone_urls)

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
            raise ConfigurationException.missing_at_least_one_key_path("/", CxOneFlowConfig.__scm_service_factories.keys())
        
        for scm in CxOneFlowConfig.__scm_service_factories.keys():

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
            if not os.path.isfile(Path(CxOneFlowConfig.__secret_root) / Path(config_dict[key])):
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
            tenant_auth_endpoint = cx.AuthRegionEndpoints[iam_endpoint_value](tenant_name)
        else:
            tenant_auth_endpoint = cx.CxOneAuthEndpoint(tenant_name, iam_endpoint_value)


        api_endpoint_value = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'api-endpoint', kwargs)
        tenant_api_endpoint = None
        if api_endpoint_value in cx.ApiRegionEndpoints.keys():
            tenant_api_endpoint = cx.ApiRegionEndpoints[api_endpoint_value]()
        else:
            tenant_api_endpoint = cx.CxOneApiEndpoint(api_endpoint_value)

        if 'api-key' in kwargs.keys():
            return cx.CxOneClient.create_with_api_key(
                CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(config_path, 'api-key', kwargs), \
                __agent__, __version__, \
                tenant_auth_endpoint, \
                tenant_api_endpoint, \
                CxOneFlowConfig.__get_value_for_key_or_default('timeout-seconds', kwargs, 60), \
                CxOneFlowConfig.__get_value_for_key_or_default('retries', kwargs, 3), \
                CxOneFlowConfig.__get_value_for_key_or_default('proxies', kwargs, None), \
                CxOneFlowConfig.__get_value_for_key_or_default('ssl-verify', kwargs, True) \
                )
        elif 'oauth' in kwargs.keys():
            oauth_params = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'oauth', kwargs)
            oauth_id = CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(f"{config_path}/oauth", 'client-id', oauth_params)
            oauth_secret = CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(f"{config_path}/oauth", 'client-secret', oauth_params)

            return cx.CxOneClient.create_with_oauth(
                oauth_id, oauth_secret, \
                __agent__, __version__, \
                tenant_auth_endpoint, \
                tenant_api_endpoint, \
                CxOneFlowConfig.__get_value_for_key_or_default('timeout-seconds', kwargs, 60), \
                CxOneFlowConfig.__get_value_for_key_or_default('retries', kwargs, 3), \
                CxOneFlowConfig.__get_value_for_key_or_default('proxies', kwargs, None), \
                CxOneFlowConfig.__get_value_for_key_or_default('ssl-verify', kwargs, True) \
                )

        return None


    __ordered_scm_config_tuples = []

    __minimum_api_auth_keys = ['token', 'password']
    __basic_auth_keys = ['username', 'password']
    __all_possible_api_auth_keys = list(set(__minimum_api_auth_keys + __basic_auth_keys))

    __minimum_clone_auth_keys = __minimum_api_auth_keys + ['ssh']
    __all_possible_clone_auth_keys = list(set(__minimum_clone_auth_keys + __basic_auth_keys))

    @staticmethod
    def __scm_api_auth_factory(config_dict, config_path):

        CxOneFlowConfig.__validate_no_extra_auth_keys(config_dict, CxOneFlowConfig.__all_possible_api_auth_keys, config_path)
        
        auth_type_keys = CxOneFlowConfig.__validate_minimum_auth_keys(config_dict, CxOneFlowConfig.__minimum_api_auth_keys, config_path)
        
        if len([x for x in config_dict.keys() if x in CxOneFlowConfig.__basic_auth_keys]) == len(CxOneFlowConfig.__basic_auth_keys):
            return auth_basic( \
                CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(config_path, 'username', config_dict), \
                CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(config_path, 'password', config_dict) )

        if 'token' in auth_type_keys:
            return auth_bearer(CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(config_path, 'token', config_dict))

        raise ConfigurationException(f"{config_path} SCM API authorization configuration is invalid!")

    @staticmethod
    def __validate_minimum_auth_keys(config_dict, valid_keys, config_path):
        auth_type_keys = [x for x in config_dict.keys() if x in valid_keys]
        if len(auth_type_keys) > 1:
            raise ConfigurationException.mutually_exclusive(config_path, auth_type_keys)
        return auth_type_keys


    @staticmethod
    def __validate_no_extra_auth_keys(config_dict, valid_keys, config_path):
        extra_passed_keys = config_dict.keys() - valid_keys

        if len(extra_passed_keys) > 0:
            raise ConfigurationException.invalid_keys(config_path, extra_passed_keys)


    @staticmethod
    def __cloner_factory(clone_auth_dict, config_path):

        CxOneFlowConfig.__validate_no_extra_auth_keys(clone_auth_dict, CxOneFlowConfig.__all_possible_clone_auth_keys, config_path)

        auth_type_keys = CxOneFlowConfig.__validate_minimum_auth_keys(clone_auth_dict, CxOneFlowConfig.__minimum_clone_auth_keys, config_path)
        
        if len([x for x in clone_auth_dict.keys() if x in CxOneFlowConfig.__basic_auth_keys]) == len(CxOneFlowConfig.__basic_auth_keys):
            return Cloner.using_basic_auth( \
                CxOneFlowConfig.__get_secret_from_value_of_key_or_fail({config_path}, 'username', clone_auth_dict), \
                CxOneFlowConfig.__get_secret_from_value_of_key_or_fail({config_path}, 'password', clone_auth_dict) )

        if 'token' in auth_type_keys:
            return Cloner.using_token_auth(CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(config_path, 'token', clone_auth_dict),
                                           CxOneFlowConfig.__get_value_for_key_or_default('username', clone_auth_dict, None))

        if 'ssh' in auth_type_keys:
            return Cloner.using_ssh_auth(Path(CxOneFlowConfig.__secret_root) / 
                                         Path(CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'ssh', clone_auth_dict)))

        raise ConfigurationException(f"{config_path} SCM clone authorization configuration is invalid!")

    @staticmethod
    def __setup_scm(scm_service_factory, config_dict, config_path):
        repo_matcher = re.compile(CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'repo-match', config_dict), re.IGNORECASE)

        service_moniker = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'service-name', config_dict)

        cxone_client = CxOneFlowConfig.__cxone_client_factory(f"{config_path}/cxone", 
                                                            **(CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'cxone', config_dict)))

        scan_config_dict = CxOneFlowConfig.__get_value_for_key_or_default('scan-config', config_dict, {} )

        cxone_service = CxOneService(service_moniker, cxone_client, \
                                     CxOneFlowConfig.__get_value_for_key_or_default('update-project-clone-creds', scan_config_dict, False), \
                                     CxOneFlowConfig.__get_value_for_key_or_default('default-scan-engines', scan_config_dict, None), \
                                     CxOneFlowConfig.__get_value_for_key_or_default('default-scan-tags', scan_config_dict, None), \
                                     CxOneFlowConfig.__get_value_for_key_or_default('default-project-tags', scan_config_dict, None), \
                                     )

        connection_config_dict = CxOneFlowConfig.__get_value_for_key_or_fail(config_path, 'connection', config_dict)


        api_auth_dict = CxOneFlowConfig.__get_value_for_key_or_fail(f"{config_path}/connection", 'api-auth', connection_config_dict)

        api_session = APISession(CxOneFlowConfig.__get_value_for_key_or_fail(f"{config_path}/connection", 'base-url', connection_config_dict), \
                                 CxOneFlowConfig.__scm_api_auth_factory(api_auth_dict, f"{config_path}/connection/api-auth"), \
                                 CxOneFlowConfig.__get_value_for_key_or_default('timeout-seconds', connection_config_dict, 60), \
                                 CxOneFlowConfig.__get_value_for_key_or_default('retries', connection_config_dict, 3), \
                                 CxOneFlowConfig.__get_value_for_key_or_default('proxies', connection_config_dict, None), \
                                 CxOneFlowConfig.__get_value_for_key_or_default('ssl-verify', connection_config_dict, True), \
                                )
        
        scm_shared_secret = CxOneFlowConfig.__get_secret_from_value_of_key_or_fail(f"{config_path}/connection", 'shared-secret', connection_config_dict)
        secret_test_result = CxOneFlowConfig.__shared_secret_policy.test(scm_shared_secret)
        if not len(secret_test_result) == 0:
            raise ConfigurationException(f"{config_path}/connection/shared-secret fails some complexity requirements: {secret_test_result}")
        
        clone_auth_dict = CxOneFlowConfig.__get_value_for_key_or_default('clone-auth', connection_config_dict, None)
        clone_config_path = f"{config_path}/connection/clone-auth"
        if clone_auth_dict is None:
            clone_auth_dict = api_auth_dict
            clone_config_path = f"{config_path}/connection/api-auth"
               
        scm_service = scm_service_factory(service_moniker, api_session, scm_shared_secret, CxOneFlowConfig.__cloner_factory(clone_auth_dict, clone_config_path))
      
        CxOneFlowConfig.__ordered_scm_config_tuples.append((repo_matcher, cxone_service, scm_service))

        
    __scm_service_factories = {'bbdc' : bitbucketdc_service_factory }

        

        


