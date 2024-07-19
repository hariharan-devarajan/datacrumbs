
# External Imports
import hydra
from omegaconf import DictConfig

# Internal Imports
from dfprofiler.common.status import ProfilerStatus

class DFProfiler:
    """
    DFProfiler Class
    """
    def __init__(self, cfg: DictConfig) -> None:
        pass

    def initialize(self) -> None:
        pass

    def run(self) -> None:
        pass

    def finalize(self) -> None:
        pass


@hydra.main(version_base=None, config_path="configs", config_name="config")
def main(cfg: DictConfig) -> int:
    """
    The main method to start the profiler runtime.
    """
    profiler = DFProfiler(cfg['module'])
    profiler.initialize()
    profiler.run()
    profiler.finalize()
    return ProfilerStatus.SUCCESS


if __name__ == '__main__':
    status:int = main()
    exit(status)