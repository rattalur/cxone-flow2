import datetime, asyncio

class Status:
    __max_retention_hours = 72
    __lock = asyncio.Lock()
    __retention_keys = {}
    __internal_state = {}
    __report_state = {}
    __start_time = None

    __bucket_gen_method = lambda: Status.__now().strftime("%Y-%m-%dT%H:00:00.000000+00:00")

    @staticmethod
    def bootstrap():
        Status.__start_time = Status.__now()
        Status.__report_state = {
            "system-start" : Status.__start_time.isoformat(),
            "uptime-seconds" : 0
        }

    @staticmethod
    def get_max_retention_hours():
        return Status.__max_retention_hours
    
    @staticmethod
    def _get_bucket_key():
        return Status.__bucket_gen_method()

    @staticmethod
    def set_bucket_gen_method(method):
        Status.__bucket_gen_method = method

    @staticmethod
    def __now():
        return datetime.datetime.now(datetime.timezone.utc)

    @staticmethod
    def __purge_old_records(moniker, operation):
        while len(Status.__retention_keys[moniker][operation]) > Status.__max_retention_hours:
            purge_key = Status.__retention_keys[moniker][operation].pop()
            del Status.__internal_state[moniker][operation][purge_key]

    @staticmethod
    def __add_purge_record(moniker, operation, bucket_key):
        Status.__retention_keys[moniker][operation].insert(0, bucket_key)

    @staticmethod
    async def get():
        async with Status.__lock:
            Status.__report_state['uptime-seconds'] = int((Status.__now() - Status.__start_time).total_seconds())
            Status.__report_state['status'] = Status.__internal_state
            return Status.__report_state

    @staticmethod
    async def report(moniker, operation, elapsed_ns):
        async with Status.__lock:

            if moniker not in Status.__internal_state.keys():
                Status.__internal_state[moniker] = {}
                Status.__retention_keys[moniker] = {}

            if operation not in Status.__internal_state[moniker].keys():
                Status.__internal_state[moniker][operation] = {}
                Status.__retention_keys[moniker][operation] = []

            bucket_key = Status._get_bucket_key()

            if bucket_key not in Status.__internal_state[moniker][operation]:
                
                Status.__add_purge_record(moniker, operation, bucket_key)

                Status.__internal_state[moniker][operation][bucket_key] = {
                    "count" : 1,
                    "total-ns" : elapsed_ns,
                    "min-ns" : elapsed_ns,
                    "max-ns" : elapsed_ns,
                    "avg-ns" : elapsed_ns
                }
            else:
                Status.__internal_state[moniker][operation][bucket_key]['count'] += 1
                Status.__internal_state[moniker][operation][bucket_key]['total-ns'] += elapsed_ns

                if elapsed_ns < Status.__internal_state[moniker][operation][bucket_key]['min-ns']:
                    Status.__internal_state[moniker][operation][bucket_key]['min-ns'] = elapsed_ns
                
                if elapsed_ns > Status.__internal_state[moniker][operation][bucket_key]['max-ns']:
                    Status.__internal_state[moniker][operation][bucket_key]['max-ns'] = elapsed_ns

                Status.__internal_state[moniker][operation][bucket_key]['avg-ns'] = \
                    int(Status.__internal_state[moniker][operation][bucket_key]['total-ns'] / \
                    Status.__internal_state[moniker][operation][bucket_key]['count'])
            
            Status.__purge_old_records(moniker, operation)

            return Status.__internal_state

            

