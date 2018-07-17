# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABVuln, VulnLevel, VulnType


class WeakPassword(ABVuln):
    vuln_id = ''  # 平台漏洞编号，留空
    name = '弱口令'  # 漏洞名称
    level = VulnLevel.SEVERITY  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''弱口令'''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    product = ''  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本
