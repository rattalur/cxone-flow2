import requests, asyncio
from _agent import __agent__
from _version import __version__
from status import Status
from time import perf_counter_ns

class CxOneException(Exception):
    pass

class CxOneService:

    def __init__(self, moniker, cxone_client, default_engines, default_scan_tags, default_project_tags):
        self.__client = cxone_client
        self.__moniker = moniker
        self.__default_project_tags = default_project_tags
        self.__default_scan_tags = default_scan_tags
        self.__default_engines = default_engines
    
    @property
    def moniker(self):
        return self.__moniker
    
    @staticmethod
    def __get_json_or_fail(response):
        if not response.ok:
            raise CxOneException(f"Method: {response.request.method} Url: {response.request.url} Status: {response.status_code}")
        else:
            return response.json()

    @staticmethod
    def __succeed_or_throw(response):
        if not response.ok:
            raise CxOneException(f"Method: {response.request.method} Url: {response.request.url} Status: {response.status_code}")


    async def execute_scan(self, zip_path, org_name, repo_name, commit_branch, repo_url, scan_tags={}):

        project_name = f"{org_name}/{repo_name}"

        check = perf_counter_ns()

        projects_response = CxOneService.__get_json_or_fail (await self.__client.get_projects(name=project_name))

        if int(projects_response['filteredTotalCount']) == 0:
            project_json = CxOneService.__get_json_or_fail (await self.__client.create_project( \
                name=project_name, origin=__agent__, tags=self.__default_project_tags | {__agent__ : __version__}))
            project_id = project_json['id']
        else:
            project_json = projects_response['projects'][0]
            project_id = project_json['id']

            new_tags = {k:self.__default_project_tags[k] \
                                     for k in self.__default_project_tags.keys() if k not in project_json['tags'].keys()}
            if len(new_tags.keys()) > 0:
                project_json['tags'] = new_tags | project_json['tags']
                CxOneService.__succeed_or_throw(await self.__client.update_project(project_id, project_json))

        await Status.report(self.moniker, "load-project", perf_counter_ns() - check)



        check = perf_counter_ns()
        upload_url = await self.__client.upload_zip(zip_path)
        await Status.report(self.moniker, "upload-zip", perf_counter_ns() - check)

        check = perf_counter_ns()
        scan_response = CxOneService.__get_json_or_fail(await self.__client.execute_scan(\
            {
            "type" : "upload",
            "handler"  : { 
                "uploadUrl" : upload_url,
                "repoUrl" : repo_url,
                "branch" : commit_branch
                },
            "tags" : scan_tags | self.__default_scan_tags,
            "config" : [] if self.__default_engines is None else \
            [{"type" : engine, "value" : self.__default_engines[engine] if self.__default_engines[engine] is not None else {} } \
             for engine in self.__default_engines.keys()], \
            "project" : {"id" : project_id}}))
        
        await Status.report(self.moniker, "submit-scan", perf_counter_ns() - check)

    