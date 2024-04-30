import logging, logging.config, json, os


def get_log_level():
    return "INFO" if os.getenv('LOG_LEVEL') is None else os.getenv('LOG_LEVEL')


def load_logging_config_dict(filename):
    with open(filename, "rt") as cfg:
        config = json.load(cfg) 
        config['loggers']['root']['level'] = get_log_level()
        return config
    
def bootstrap():
        logging.config.dictConfig({
            "version": 1,
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout"
                },
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "formatter": "default",
                    "filename": f"/var/log/cxoneflow/cxoneflow.{os.getpid()}.log",
                    "backupCount" : 10,
                    "maxBytes" : 1024000000
                }

            },
            "formatters": {
                "default": {
                    "format": "[%(asctime)s][%(process)d][%(name)s][%(levelname)s] %(message)s",
                    "datefmt": "%Y-%m-%dT%H:%M:%S%z"
                }
            },
            "loggers": {
                "root": {
                    "handlers": ["console", "file"],
                    "level": "DEBUG"
                }
            }
        })
