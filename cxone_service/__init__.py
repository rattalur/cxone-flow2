import requests, asyncio

class CxOneException:
    pass

class CxOneService:

    def __init__(self, cxone_client, update_clone_creds, default_engines, default_scan_tags, default_project_tags):
        self.__client = cxone_client

    async def execute_scan(self, zip_path, org_name, repo_name, commit_branch, commit_hash):

        project_name = f"{org_name}-{repo_name}"

        projects_response = await self.__client.get_projects(name=project_name)
        # Lookup project
            # Create if not found
        # set project tags
        # update clone creds (?)


        upload_url = await self.__client.upload_zip(zip_path)

        pass

    