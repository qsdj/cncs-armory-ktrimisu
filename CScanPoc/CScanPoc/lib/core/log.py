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

    OUTPUT_HANDLER = colorlog.StreamHandler(sys.stdout)
    OUTPUT_HANDLER.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s'))

    OUTPUT = logging.getLogger("CScanOutputer")
    OUTPUT.addHandler(OUTPUT_HANDLER)
    OUTPUT.setLevel(CScanOutputLevel.INFO)

    JSON_OUTPUT = False

    @staticmethod
    def set_json_output():
        CScanOutputer.JSON_OUTPUT = True
        formatter = jsonlogger.JsonFormatter()
        CScanOutputer.OUTPUT_HANDLER.setFormatter(formatter)

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
