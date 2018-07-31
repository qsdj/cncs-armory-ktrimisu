# coding: utf-8

import logging
import sys
import colorlog
from pythonjsonlogger import jsonlogger

# CScan 日志记录
CSCAN_LOGGER = logging.getLogger('CScanPocLogger')


def setup_cscan_poc_logger(level=None, verbose=False, very_verbose=False):
    '''CScan 全局日志'''
    # 清除 logging 默认日志输出
    logging.getLogger().handlers.clear()
    output_handler = colorlog.StreamHandler(sys.stdout)
    output_handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s'))
    CSCAN_LOGGER.addHandler(output_handler)
    if level is not None:
        CSCAN_LOGGER.setLevel(level)
    else:
        if very_verbose:
            CSCAN_LOGGER.setLevel(logging.DEBUG)
        elif verbose:
            CSCAN_LOGGER.setLevel(logging.INFO)
        else:
            CSCAN_LOGGER.setLevel(logging.WARNING)
    return CSCAN_LOGGER


class CScanOutputLevel:
    '''CScan 结果输出级别'''
    INFO = 20
    WARN = 40
    REPORT = 60

    @staticmethod
    def from_string(lvl):
        '''
        转换字符串未日志级别（不区分大小写），默认 INFO

        Args:
          m (str) : 级别的字符串名
        '''
        return {
            'info': CScanOutputLevel.INFO,
            'warn': CScanOutputLevel.WARN,
            'report': CScanOutputLevel.REPORT
        }.get(lvl.lower(), CScanOutputLevel.INFO)


class CScanOutputer:
    '''CScan 结果输出记录器'''

    def __init__(self, logger, poc=None, strategy=None):
        '''
        :param logger: 日志记录器
        '''
        self.logger = logger
        self.poc = poc
        self.strategy = strategy

    def get_extra(self, vuln=None):
        extra = {'hello': 'world'}
        if self.poc:
            extra['poc'] = self.poc
        if self.strategy:
            extra['strategy'] = self.strategy
        if vuln:
            extra['vuln'] = vuln
        return extra

    def msg_with_extra(self, msg):
        if self.poc:
            msg = '%s %s' % (self.poc, msg)
        if self.strategy:
            msg = '%s %s' % (self.strategy, msg)
        return msg

    def info(self, msg):
        '''
        输出漏洞扫描过程中一般执行日志、流程信息
        '''
        self.logger.log(CScanOutputLevel.INFO,
                        self.msg_with_extra(msg),
                        extra=self.get_extra())

    def warning(self, vuln, msg):
        '''
        输出扫出的和漏洞 vuln 相关的疑似漏洞的警告信息
        '''
        self.warn(vuln, msg)

    def warn(self, vuln, msg):
        '''同 warning'''
        self.logger.log(CScanOutputLevel.WARN,
                        self.msg_with_extra(msg),
                        extra=self.get_extra(vuln))

    def report(self, vuln, msg):
        '''
        输出扫出的和漏洞 vuln 相关的漏洞信息
        '''
        self.logger.log(CScanOutputLevel.REPORT,
                        self.msg_with_extra(msg),
                        extra=self.get_extra(vuln))


def _get_json_translate():
    from CScanPoc.lib.api.vuln import ABVuln
    from CScanPoc.lib.api.poc import ABPoc
    from CScanPoc.lib.api.strategy import ABStrategy

    def _json_translate(obj):
        '''JSON logger translate'''
        if isinstance(obj, ABVuln):
            return obj.vuln_id
        if isinstance(obj, ABPoc):
            return obj.poc_id
        if isinstance(obj, ABStrategy):
            return obj.strategy_id

    return _json_translate


# CScan 输出记录器使用的 logger
__CSCAN_OUTPUT_LOGGER = logging.getLogger('CScanOutputer')


def get_scan_outputer(poc=None, strategy=None):
    return CScanOutputer(__CSCAN_OUTPUT_LOGGER, poc=poc, strategy=strategy)


def setup_cscan_outputer(json_output=False, poc=None, strategy=None):
    '''设定 CScan 结果输出记录器'''
    logging.addLevelName(CScanOutputLevel.INFO, 'INFO')
    logging.addLevelName(CScanOutputLevel.WARN, 'WARN')
    logging.addLevelName(CScanOutputLevel.REPORT, 'REPORT')

    __CSCAN_OUTPUT_LOGGER.handlers.clear()
    # 清除 logging 默认日志输出
    logging.getLogger().handlers.clear()

    output_handler = colorlog.StreamHandler(sys.stdout)
    output_handler.setFormatter(colorlog.ColoredFormatter(
        '> %(log_color)s[%(asctime)s] [%(levelname)s] %(message)s'))
    __CSCAN_OUTPUT_LOGGER.addHandler(output_handler)
    __CSCAN_OUTPUT_LOGGER.setLevel(CScanOutputLevel.INFO)

    if json_output:
        CSCAN_LOGGER.info('输出 JSON')
        output_handler = logging.StreamHandler(sys.stdout)
        output_handler.setFormatter(jsonlogger.JsonFormatter(
            '(asctime) (vuln) (poc) (strategy) (hello) (levelname) (message)',
            json_default=_get_json_translate()))
        __CSCAN_OUTPUT_LOGGER.addHandler(output_handler)
