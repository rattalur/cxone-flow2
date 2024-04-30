import logging, logging.config, json, os


def get_log_level():
    return "INFO" if os.getenv('LOG_LEVEL') is None else os.getenv('LOG_LEVEL')

def get_log_config_filename():
    return os.getenv('CXONEFLOW_LOG_CONFIG_FILE')


def load_logging_config_dict(filename):
    with open(filename, "rt") as cfg:
        config = json.load(cfg) 
        config['loggers']['root']['level'] = get_log_level()
        return config
    
def bootstrap(filename=get_log_config_filename()):
    if filename is None:
        logging.config.dictConfig({
            "version": 1,
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout"
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
                    "handlers": ["console"],
                    "level": "DEBUG"
                }
            }
        })
    else:
        logging.config.dictConfig(load_logging_config_dict(filename))