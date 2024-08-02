# Python Native Imports
from typing import *
import os
import pathlib
import logging

# External Imports
from omegaconf import DictConfig

# Internal Imports
from datacrumbs.common.utils import convert_or_fail


class ConfigurationManager:
    # singleton instance
    __instance = None
    project_root: str
    # Configuration variables
    user_libraries: Dict[str, str] = {}
    interval_sec: float
    module: str
    install_dir: str
    profile_file: str

    @staticmethod
    def get_instance():
        """Static access method."""
        if ConfigurationManager.__instance is None:
            ConfigurationManager.__instance = ConfigurationManager()
        return ConfigurationManager.__instance

    def __init__(self):
        self.project_root = pathlib.Path(__file__).parent.parent.parent.resolve()
        log_file = "datacrumbs.log"
        try:
            os.remove(log_file)
        except OSError:
            pass
        logging.basicConfig(
            level=logging.DEBUG,
            handlers=[
                logging.FileHandler(log_file, mode="a", encoding="utf-8"),
                logging.StreamHandler(),
            ],
            format="%(asctime)s [%(levelname)s]: %(message)s in %(pathname)s:%(lineno)d",
        )
        pass

    def load(self, config: DictConfig):
        if "name" in config:
            self.module = config["name"]
        if "install_dir" in config:
            self.install_dir = config["install_dir"]
            if not os.path.isabs(self.install_dir):
                self.install_dir = os.path.join(self.project_root, self.install_dir)
        if "file" in config:
            self.profile_file = config["file"]
        if "user" in config:
            for obj in config["user"]:
                self.user_libraries[obj["name"]] = obj
        if "profile" in config:
            if "interval_sec" in config["profile"]:
                status, self.interval_sec = convert_or_fail(
                    float, config["profile"]["interval_sec"]
                )
                if status.failed():
                    exit(status)
        return self
