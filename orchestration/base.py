import zipfile, tempfile
from pathlib import Path, PurePath

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
    
    @staticmethod
    def __get_path_dict(path, root=None):
        return_dict = {}

        use_root = path if root is None else root

        p = Path(path)

        for entry in p.iterdir():
            if entry.is_dir():
                return_dict |= OrchestratorBase.__get_path_dict(entry, use_root)
            else:
                return_dict[entry] = PurePath(entry).relative_to(use_root)
        return return_dict
    
    def get_header_key_safe(self, key):
        try:
            return self.__headers[key]
        except:
            return None

    async def execute(self, cxone_service, scm_service):
        raise NotImplementedError("execute")
    
    async def _execute_push_scan_workflow(self, cxone_service, scm_service):
        protected_branches = await scm_service.get_protected_branches(self._repo_project_key, self._repo_slug)
        commit_branch, commit_hash = await self._get_target_branch_and_hash()

        if commit_branch in protected_branches:
            async with scm_service.cloner.clone(self._repo_clone_url(scm_service.cloner.clone_protocol)) as clone_worker:
                code_path = await clone_worker.loc()

                await scm_service.cloner.reset_head(code_path, commit_hash)

                with zipfile.ZipFile("/tmp/test.zip", mode="w") as upload_payload:
                    zip_entries = OrchestratorBase.__get_path_dict(code_path)
                    for entry_key in zip_entries.keys():
                        upload_payload.write(entry_key, zip_entries[entry_key])
                    pass


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
    def _repo_project_key(self):
        raise NotImplementedError("_repo_project_key")

    @property
    def _repo_slug(self):
        raise NotImplementedError("_repo_slug")

    def _repo_clone_url(self, protocol=None):
        raise NotImplementedError("_repo_clone_uri")

    @property
    def _repo_name(self):
        raise NotImplementedError("_repo_name")
    
    @property
    def is_diagnostic(self):
        raise NotImplementedError("is_diagnostic")
    


