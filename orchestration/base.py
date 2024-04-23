
class OrchestratorBase:

    def __init__(self, headers, webhook_payload):
        self.__webhook_payload = webhook_payload
        self.__headers = headers

    @property
    def _headers(self):
        return self.__headers

    @property
    def route_urls(self):
        raise NotImplementedError("route_urls")

    @property
    def _webhook_payload(self):
        return self.__webhook_payload
    
    def get_header_key_safe(self, key):
        try:
            return self.__headers[key]
        except:
            return None

    async def execute(self, cxone_service, scm_service):
        raise NotImplementedError("execute")
    
    async def _execute_push_scan_workflow(self, cxone_service, scm_service):
        protected_branches = await scm_service.get_protected_branches(await self._repo_project_key, await self._repo_slug)
        commit_branch, commit_hash = await self._get_target_branch_and_hash()

        if commit_branch in protected_branches:
            pass
            # Clone at hash
            # Zip the source
            # scan with:
            # * hash has a tag
            # * branch name
            # * service adds rest of config options to scan, creates project with tags if needed.
            # 
        return 204

    async def _execute_pr_scan_workflow(self, cxone_service, scm_service):
        pass
        
    
    async def _get_target_branch_and_hash(self):
        raise NotImplementedError("_get_target_branch_and_hash")


    async def is_signature_valid(self, shared_secret):
        raise NotImplementedError("is_signature_valid")
    
    @property
    async def _repo_project_key(self):
        raise NotImplementedError("_repo_project_key")

    @property
    async def _repo_slug(self):
        raise NotImplementedError("_repo_slug")

    @property
    async def _repo_clone_uri(self, protocol=None):
        raise NotImplementedError("_repo_clone_uri")

    @property
    async def _repo_name(self):
        raise NotImplementedError("_repo_name")
    
    @property
    def is_diagnostic(self):
        raise NotImplementedError("is_diagnostic")
    


