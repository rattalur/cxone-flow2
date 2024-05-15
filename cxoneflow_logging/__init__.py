import logging, logging.config, json, os, pathlib, re

class RedactingStreamHandler(logging.StreamHandler):
     
    __secret_matcher = re.compile("Authorization: .+ (?P<header>.*)$|http[s]?://(?P<url>.*?:.*?)@", re.RegexFlag.I | re.RegexFlag.M)

    def format(self, record):
        msg = super().format(record)
        for secret in RedactingStreamHandler.__secret_matcher.finditer(msg):
            for m in secret.groupdict().keys():
                msg = msg[0:secret.start(m)] + ('*' * (secret.end(m) - secret.start(m))) + msg[secret.end(m):]
        
        return msg


def get_log_level():
    return "INFO" if os.getenv('LOG_LEVEL') is None else os.getenv('LOG_LEVEL')


def load_logging_config_dict(filename):
    with open(filename, "rt") as cfg:
        config = json.load(cfg) 
        config['loggers']['root']['level'] = get_log_level()
        return config
    
def bootstrap():
        
        dest_file_path = f"/var/log/cxoneflow/cxoneflow.{os.getpid()}.log"

        dir = os.path.dirname(dest_file_path)

        if not os.path.exists(dir):
             dest_file_path = pathlib.Path(".") / pathlib.Path(dest_file_path).name
        
        log_cfg = {
            "version": 1,
            "handlers": {
                "console": {
                    "class": "cxoneflow_logging.RedactingStreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout"
                },
                # "file": {
                #     "class": "logging.handlers.RotatingFileHandler",
                #     "formatter": "default",
                #     "filename": dest_file_path,
                #     "backupCount" : 10,
                #     "maxBytes" : 1024000000
                # }
            },
            "formatters": {
                "default": {
                    "format": "[%(asctime)s][%(process)d][%(name)s][%(levelname)s] %(message)s",
                    "datefmt": "%Y-%m-%dT%H:%M:%S%z"
                }
            },
            "loggers": {
                "root": {
                    "handlers": ["console"],
                    "level": get_log_level()
                }
            }
        }

        logging.config.dictConfig(log_cfg)
