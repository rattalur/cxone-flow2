from .scm import SCMService


class BitBucketDataCenterService(SCMService):

    def __init__(self, session, shared_secret, cloner):
        SCMService.__init__(self, session, shared_secret, cloner)

    async def get_protected_branches(self, project, slug):
        retBranches = []
        json = (await self._exec("GET", f"/rest/branch-utils/latest/projects/{project}/repos/{slug}/branchmodel")).json()
        
        if 'development' in json.keys() and 'displayId' in json['development'].keys():
            retBranches.append(json['development']['displayId'])
        
        if 'production' in json.keys() and 'displayId' in json['production'].keys():
            retBranches.append(json['production']['displayId'])
        
        return list(set(retBranches))

    async def get_default_branch(self, project, slug):
        json =  (await self._exec("GET", f"/rest/api/latest/projects/{project}/repos/{slug}/default-branch")).json()
        return json['displayId'] if "displayId" in json.keys() else ""

