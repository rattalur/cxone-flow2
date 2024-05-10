from .base import OrchestratorBase
import json, base64, urllib, urllib.parse
from jsonpath_ng import parse
from cxone_api.util import CloneUrlParser


class AzureDevOpsEnterpriseOrchestrator(OrchestratorBase):

    __diag_subid = "00000000-0000-0000-0000-000000000000"
    __subid_query = parse("$.subscriptionId")
    __remoteurl_query = parse("$.resource.repository.remoteUrl")
    __default_branch_query = parse("$.resource.repository.defaultBranch")
    __repo_project_key_query = parse("$.resource.repository.project.name")
    __repo_slug_query = parse("$.resource.repository.name")
    __payload_type_query = parse("$.eventType")
    __target_branch_query = parse("$.resource.refUpdates..name")
    __target_hash_query = parse("$.resource.refUpdates..newObjectId")


    def __init__(self, headers, webhook_payload):
        OrchestratorBase.__init__(self, headers, webhook_payload)

        self.__json = json.loads(webhook_payload)
      
        self.__isdiagnostic = AzureDevOpsEnterpriseOrchestrator.__diag_subid in [x.value for x in list(AzureDevOpsEnterpriseOrchestrator.__subid_query.find(self.__json))]
        if self.__isdiagnostic:
            return

        self.__event = [x.value for x in list(self.__payload_type_query.find(self.__json))][0]
        self.__route_urls = [x.value for x in list(self.__remoteurl_query.find(self.__json))]
        self.__clone_url = self.__route_urls[0]
        self.__default_branches = [AzureDevOpsEnterpriseOrchestrator.__normalize_branch_name(x.value) for x in list(self.__default_branch_query.find(self.__json))]
        self.__repo_key = [x.value for x in list(self.__repo_project_key_query.find(self.__json))][0]
        self.__repo_slug = [x.value for x in list(self.__repo_slug_query.find(self.__json))][0]

    async def execute(self, cxone_service, scm_service):
        return await AzureDevOpsEnterpriseOrchestrator.__workflow_map[self.__event](self, cxone_service, scm_service)

    @staticmethod
    def __normalize_branch_name(branch):
        return branch.split("/")[-1:].pop()

    @property
    def is_diagnostic(self):
        return self.__isdiagnostic

    @property
    def route_urls(self):
        return self.__route_urls

    @property
    def _repo_project_key(self):
        return self.__repo_key

    @property
    def _repo_name(self):
        return self.__repo_slug

    @property
    def _repo_slug(self):
        return urllib.parse.quote(self.__repo_slug)
    
    async def is_signature_valid(self, shared_secret):
        base64_payload = self._headers['Authorization'].split(" ")[-1:].pop()
        sent_secret = base64.b64decode(base64_payload).decode("utf-8").split(":")[-1:].pop()
        return sent_secret == shared_secret


    def _repo_clone_url(self, cloner):
        parsed_clone_url = urllib.parse.urlparse(self.__clone_url)

        if parsed_clone_url.scheme in cloner.supported_protocols:
            return self.__clone_url
        
        protocol = cloner.supported_protocols[0]
        port = cloner.destination_port

        return urllib.parse.urlunparse((protocol, f"{parsed_clone_url.netloc}{f":{port}" if port is not None else ""}", 
                                       parsed_clone_url.path, parsed_clone_url.params, parsed_clone_url.query, parsed_clone_url.fragment))
    
    async def _get_protected_branches(self, scm_service):
        # TODO: Default branch is in webhook payload, but there is a branch control mechanism
        # used to specify deployment branches.  The deployment branches should merge with the default branch.
        return self.__default_branches

    async def _get_target_branch_and_hash(self):
        first_target_branch = AzureDevOpsEnterpriseOrchestrator.__normalize_branch_name([x.value for x in list(self.__target_branch_query.find(self.__json))][0])
        first_target_hash = [x.value for x in list(self.__target_hash_query.find(self.__json))][0]
        return first_target_branch, first_target_hash

    async def get_cxone_project_name(self):
        p = CloneUrlParser("azure", self.__clone_url)
        return f"{p.org}/{self._repo_project_key}/{self._repo_name}"


    __workflow_map = {
        "git.push" : OrchestratorBase._execute_push_scan_workflow,
        "git.pullrequest.created" : OrchestratorBase._execute_pr_scan_workflow
    }
