# coding: utf-8

import logging
import sys
import colorlog
from pythonjsonlogger import jsonlogger


class CScanOutputLevel:
    INFO = 20
    WARN = 40
    REPORT = 60

    @staticmethod
    def fromString(lvl):
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
    logging.addLevelName(CScanOutputLevel.INFO, 'INFO')
    logging.addLevelName(CScanOutputLevel.WARN, 'WARN')
    logging.addLevelName(CScanOutputLevel.REPORT, 'REPORT')

    JSON_OUTPUT = False
    OUTPUT = logging.getLogger("CScanOutputer")
    OUTPUT.setLevel(CScanOutputLevel.INFO)

    @staticmethod
    def init_output(json_output=False):
        CScanOutputer.OUTPUT.handlers.clear()
        logging.getLogger().handlers.clear()
        if json_output:
            CScanOutputer.JSON_OUTPUT = True
            output_handler = logging.StreamHandler(sys.stdout)
            formatter = jsonlogger.JsonFormatter(
                '(asctime) (vuln) (levelname) (message)')
            output_handler.setFormatter(formatter)
            CScanOutputer.OUTPUT.addHandler(output_handler)
        else:
            output_handler = colorlog.StreamHandler(sys.stdout)
            output_handler.setFormatter(colorlog.ColoredFormatter(
                '%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s'))
            CScanOutputer.OUTPUT.addHandler(output_handler)

    @staticmethod
    def info(msg):
        '''
        输出漏洞扫描过程中一般执行日志、流程信息
        '''
        CScanOutputer.OUTPUT.log(
            CScanOutputLevel.INFO, '{msg}'.format(msg=msg))

    @staticmethod
    def warning(msg):
        CScanOutputer.OUTPUT.log(
            CScanOutputLevel.WARN, '{msg}'.format(msg=msg))

    @staticmethod
    def warn(vuln, msg):
        '''
        输出扫出的和漏洞 vuln 相关的疑似漏洞信息
        '''
        if CScanOutputer.JSON_OUTPUT:
            CScanOutputer.OUTPUT.log(
                CScanOutputLevel.WARN, msg, extra={'vuln_id': vuln.vuln_id})
        else:
            CScanOutputer.OUTPUT.log(
                CScanOutputLevel.WARN, '{vuln} {msg}'.format(vuln=vuln, msg=msg))

    @staticmethod
    def report(vuln, msg):
        '''
        输出扫出的和漏洞 vuln 相关的漏洞信息
        '''
        if CScanOutputer.JSON_OUTPUT:
            CScanOutputer.OUTPUT.log(
                CScanOutputLevel.REPORT, msg, extra={'vuln_id': vuln.vuln_id})
        else:
            CScanOutputer.OUTPUT.log(
                CScanOutputLevel.REPORT,
                '{vuln} {msg}'.format(vuln=vuln, msg=msg))
