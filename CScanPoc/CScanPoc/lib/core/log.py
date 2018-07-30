# coding: utf-8

import logging
import sys
import colorlog


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
        CScanOutputer.OUTPUT.log(
            CScanOutputLevel.WARN, '{vuln} {msg}'.format(vuln=vuln, msg=msg))

    @staticmethod
    def report(vuln, msg):
        '''
        输出扫出的和漏洞 vuln 相关的漏洞信息
        '''
        CScanOutputer.OUTPUT.log(
            CScanOutputLevel.REPORT, '{vuln} {msg}'.format(vuln=vuln, msg=msg))
