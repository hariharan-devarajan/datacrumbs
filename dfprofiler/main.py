# External Imports
import hydra
from omegaconf import DictConfig
import logging

# Internal Imports
from dfprofiler.dfbcc.dfbcc import BCCMain
from dfprofiler.common.status import ProfilerStatus
from dfprofiler.configs.configuration_manager import ConfigurationManager


class DFProfiler:
    """
    DFProfiler Class
    """

    def __init__(self, cfg: DictConfig) -> None:
        self.config = ConfigurationManager.get_instance().load(cfg)

    def initialize(self) -> None:
        self.bcc = BCCMain().load()

    def run(self) -> None:
        self.bcc.run()

    def finalize(self) -> None:
        logging.info("Detaching...")


@hydra.main(version_base=None, config_path="configs", config_name="config")
def main(cfg: DictConfig) -> int:
    """
    The main method to start the profiler runtime.
    """
    profiler = DFProfiler(cfg["module"])
    profiler.initialize()
    profiler.run()
    profiler.finalize()
    return ProfilerStatus.SUCCESS


if __name__ == "__main__":
    status: int = main()
    exit(status)
