import os


def cfg_patch_db(config: dict):
    # force to use PostgreSQL instead of the default badgerv2
    PG_HOST = os.environ["PG_HOST"]
    PG_PORT = os.environ["PG_PORT"]
    POSTGRES_USER = os.environ["POSTGRES_USER"]
    POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]

    config["db"] = {
        "type": "postgresql",
        "dataSource": f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{PG_HOST}:{PG_PORT}/stepca",
        "database": "stepca",
        "badgerFileLoadingMode": ""
    }

    return config


def cfg_patch_remote_admin(config: dict):
    # re-enable remote management to force migration of the default
    # provisioners from the ca.json config to the database
    if "authority" not in config:
        config["authority"] = {}

    config["authority"]["enableAdmin"] = True
    return config
