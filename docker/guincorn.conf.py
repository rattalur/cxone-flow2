from multiprocessing import cpu_count
from task_management import TaskManager
import os

if "CXONEFLOW_WORKERS" not in os.environ.keys():
    workers = cpu_count() / 2
else:
    workers = min(cpu_count() - 1, int(os.environ['CXONEFLOW_WORKERS']))

timeout = 90
graceful_timeout=600

daemon = True
max_requests = 500

bind="127.0.0.1:5000"

accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"
if "LOG_LEVEL" not in os.environ.keys():
    loglevel="INFO"
else:
    loglevel=os.environ['LOG_LEVEL']


def worker_exit(server, worker):
    TaskManager.wait_for_exit()

