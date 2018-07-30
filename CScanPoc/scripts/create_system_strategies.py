# coding: utf-8

template = """
# coding: utf-8

import logging
from CScanPoc import ABStrategy

class Strategy(ABStrategy):
    def __init__(self, index_dir=None):
        self.index_dir = index_dir

    def name(self):
        '''策略名'''
        return {strategy_name}

    def pocs(self):
        '''使用到的 POC ID 列表'''
        return {poc_ids}

    def run(self):
        for poc_id in self.pocs:
            poc = None
            try:
                poc = self.get_poc(poc_id)
            except:
                logging.exception('POC[id=%s]加载失败', poc_id)
            try:
                poc.run()
            except:
                logging.exception('%s 执行异常', poc)
"""
