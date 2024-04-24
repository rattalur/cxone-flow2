from .base import OrchestratorBase
import json
from api_utils import signature
from jsonpath_ng import parse

class BitBucketDataCenterOrchestrator(OrchestratorBase):

    __route_urls_query = parse("$.repository.links.clone[*]")
    __repo_project_key_query = parse("$.repository.project.key")
    __repo_slug_query = parse("$.repository.slug")
    __repo_name_query = parse("$.repository.name")
    __changes_extract_query = parse("$.changes[*]")
    __change_types_query = parse("$.changes[*].type")

    __push_scannable_change_types = ['ADD', 'UPDATE']


    def __init__(self, headers, webhook_payload):
        OrchestratorBase.__init__(self, headers, webhook_payload)
        
        self.__isdiagnostic = False

        self.__event = self.get_header_key_safe('X-Event-Key') 

        if not self.__event is None and self.__event == "diagnostics:ping":
            self.__isdiagnostic = True
            return

        self.__json = json.loads(webhook_payload)

        self.__clone_urls = {x.value['name']:x.value['href'] for x in BitBucketDataCenterOrchestrator.__route_urls_query.find(self.__json) }
        self.__route_urls = list(self.__clone_urls.values())


    @property
    def route_urls(self):
        return self.__route_urls

    async def is_signature_valid(self, shared_secret):
        sig = self.get_header_key_safe('X-Hub-Signature')
        if sig is None:
            return False
        
        hashalg,hash = sig.split("=")
        payload_hash = signature.get(hashalg, shared_secret, self._webhook_payload)

        return hash == payload_hash


    async def execute(self, cxone_service, scm_service):
        return await BitBucketDataCenterOrchestrator.__workflow_map[self.__event](self, cxone_service, scm_service)

    async def _execute_push_scan_workflow(self, cxone_service, scm_service):
        self.__repo_project_key = BitBucketDataCenterOrchestrator.__repo_project_key_query.find(self.__json)[0].value
        self.__repo_slug = BitBucketDataCenterOrchestrator.__repo_slug_query.find(self.__json)[0].value
        self.__repo_name = BitBucketDataCenterOrchestrator.__repo_name_query.find(self.__json)[0].value
        
        return await OrchestratorBase._execute_push_scan_workflow(self, cxone_service, scm_service)


    async def _get_target_branch_and_hash(self):

        if len([x.value for x in BitBucketDataCenterOrchestrator.__change_types_query.find(self.__json) \
                if x.value in BitBucketDataCenterOrchestrator.__push_scannable_change_types]) > 0:
            
            first_change = BitBucketDataCenterOrchestrator.__changes_extract_query.find(self.__json)[0].value

            return first_change['ref']['displayId'], first_change['toHash']

        return None


    @property
    def _repo_project_key(self):
        return self.__repo_project_key

    @property
    def _repo_slug(self):
        return self.__repo_slug

    def _repo_clone_url(self, protocol=None):
        if protocol is None or protocol not in self.__clone_urls.keys():
            return self.__route_urls[0]
        else:
            return self.__clone_urls[protocol]
        
    @property
    def _repo_name(self):
        return self.__repo_name
        
    @property
    def is_diagnostic(self):
        return self.__isdiagnostic

    __workflow_map = {
        "repo:refs_changed" : _execute_push_scan_workflow,
        "pr:opened" : OrchestratorBase._execute_pr_scan_workflow,
        "pr:from_ref_updated" : OrchestratorBase._execute_pr_scan_workflow

        # non-scan
        # "pr:modified" : OrchestratorBase._execute_pr_scan_workflow
        # pr:declined
        # pr:deleted
        # pr:reviewer:unapproved
        # pr:reviewer:approved
        # pr:reviewer:needs_work
        # pr:merged
    }
