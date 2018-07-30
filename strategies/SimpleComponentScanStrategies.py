from CScanPoc import ABStrategy
from CScanPoc.lib.utils.indexing import iter_pocs_of_component


class SimpleComponentScanStrategies(ABStrategy):
    def __init__(self, component_name):
        ABStrategy.__init__(self)
        self._name = component_name

    @property
    def name(self):
        return self._name

    @property
    def pocs(self):
        return iter_pocs_of_component(self.name, self.index_dir)


if __name__ == '__main__':
    SimpleComponentScanStrategies('CmsEasy').run()
