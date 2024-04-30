import os, tempfile, shutil, shlex, subprocess, asyncio, logging, urllib, base64


class Cloner:

    def __init__(self):
        self.__env = dict(os.environ)

    @staticmethod
    def log():
        return logging.getLogger("Cloner")

    @staticmethod
    def __insert_creds_in_url(url, username, password):
        split = urllib.parse.urlsplit(url)
        new_netloc = f"{urllib.parse.quote(username, safe='') if username is not None else 'git'}:{urllib.parse.quote(password, safe='')}@{split.netloc}"
        return urllib.parse.urlunsplit((split.scheme, new_netloc, split.path, split.query, split.fragment))
        
    @staticmethod
    def using_basic_auth(username, password):
        Cloner.log().debug("Clone with using_basic_auth")

        retval = Cloner()
        retval.__protocol = "https"
        retval.__username = username
        retval.__password = password

        encoded_creds = base64.b64encode(f"{username}:{password}".encode('UTF8')).decode('UTF8')

        retval.__clone_cmd_stub = ["git", "clone", "-c", f"http.extraHeader=Authorization: Basic {encoded_creds}"]
        retval.__fix_clone_url = lambda url: Cloner.__insert_creds_in_url(url, username, password)

        return retval

    @staticmethod
    def using_token_auth(token, username=None):
        Cloner.log().debug("Clone with using_token_auth")

        retval = Cloner()
        retval.__protocol = "https"

        retval.__clone_cmd_stub = ["git", "clone", "-c", f"http.extraHeader=Authorization: Bearer {token}"]

        retval.__fix_clone_url = lambda url: Cloner.__insert_creds_in_url(url, username, token)

        return retval

    @staticmethod
    def using_ssh_auth(ssh_private_key_file):
        Cloner.log().debug("Clone with using_ssh_auth")

        retval = Cloner()
        retval.__protocol = "ssh"
        with open(ssh_private_key_file, "rt") as source:
            with tempfile.NamedTemporaryFile(mode="wt", delete_on_close=False, delete=False) as dest:
                shutil.copyfileobj(source, dest)
                retval.__keyfile = dest.file.name

        retval.__env['GIT_SSH_COMMAND'] = f"ssh -i '{shlex.quote(retval.__keyfile)}' -o IdentitiesOnly=yes -oStrictHostKeyChecking=accept-new"
        retval.__clone_cmd_stub = ["git", "clone"]

        retval.__fix_clone_url = lambda url: url

        return retval
    
    @property
    def clone_protocol(self):
        return self.__protocol

    def clone(self, clone_url):
        Cloner.log().debug(f"Clone Execution for: {clone_url}")

        fixed_clone_url = self.__fix_clone_url(clone_url)

        clone_output_loc = tempfile.TemporaryDirectory(delete=False)
        thread = asyncio.to_thread(subprocess.run, self.__clone_cmd_stub + [fixed_clone_url, clone_output_loc.name], \
                                   capture_output=True, env=self.__env, check=True)
        
        return Cloner.__clone_worker(thread, clone_output_loc)

    async def reset_head(self, code_path, hash):
        try:
            result = await (asyncio.to_thread(subprocess.run, ["git", "reset", "--hard", hash], \
                                capture_output=True, env=self.__env, check=True, cwd=code_path))
            
            self.log().debug(f"Reset task: return code [{result.returncode}] stdout: [{result.stdout}] stderr: [{result.stderr}]")

        except subprocess.CalledProcessError as ex:
            self.log().error(f"{ex} stdout: [{ex.stdout.decode('UTF-8')}] stderr: [{ex.stderr.decode('UTF-8')})]")
            raise

    class __clone_worker:

        def __init__(self, clone_thread, clone_dest_path):
            self.__log = logging.getLogger(f"__clone_worker:{clone_thread}")
            self.__clone_out_tempdir = clone_dest_path
            self.__clone_thread = clone_thread

        
        async def loc(self):
            try:
                completed = await self.__clone_thread
                self.__log.debug(f"Clone task: return code [{completed.returncode}] stdout: [{completed.stdout}] stderr: [{completed.stderr}]")
                return self.__clone_out_tempdir.name
            except subprocess.CalledProcessError as ex:
                self.__log.error(f"{ex} stdout: [{ex.stdout.decode('UTF-8')}] stderr: [{ex.stderr.decode('UTF-8')})]")
                raise

        async def __aenter__(self):
            self.__log.debug("__aenter__")
            return self

        async def __aexit__(self, exc_type, exc, tb):
            self.__log.debug("__aexit__")
            self.__clone_out_tempdir.cleanup()



