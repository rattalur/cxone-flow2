import requests, asyncio
from _agent import __agent__
from _version import __version__
from time import perf_counter_ns
from cxone_api.scanning import ScanInvoker
from cxone_api.projects import ProjectRepoConfig

class CxOneException(Exception):
    pass

class CxOneService:

    __minimum_engine_selection = ['sast']

    def __init__(self, moniker, cxone_client, default_engines, default_scan_tags, default_project_tags):
        self.__client = cxone_client
        self.__moniker = moniker
        self.__default_project_tags = default_project_tags if default_project_tags is not None else {}
        self.__default_scan_tags = default_scan_tags if default_scan_tags is not None else {}
        self.__default_engines = default_engines
    
    @property
    def moniker(self):
        return self.__moniker
    
    @staticmethod
    def __get_json_or_fail(response):
        if not response.ok:
            raise CxOneException(f"Method: {response.request.method} Url: {response.request.url} Status: {response.status_code} Body: {response.text}")
        else:
            return response.json()

    @staticmethod
    def __succeed_or_throw(response):
        if not response.ok:
            raise CxOneException(f"Method: {response.request.method} Url: {response.request.url} Status: {response.status_code}")
        else:
            return response


    async def execute_scan(self, zip_path, project_name, commit_branch, repo_url, scan_tags={}):

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

        project_config = await ProjectRepoConfig.from_loaded_json(self.__client, project_json)

        engines = self.__default_engines

        if engines is None:
            engines = await project_config.get_enabled_scanners(commit_branch)

        if len(engines) == 0:
            engines = CxOneService.__minimum_engine_selection

        return CxOneService.__get_json_or_fail(await ScanInvoker.scan_get_response(self.__client, 
                project_config, commit_branch, engines, scan_tags | self.__default_scan_tags, zip_path))
   