# coding: utf-8

from CScanPoc import ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'sql-injection'  # 平台漏洞编号
    name = 'SQL 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-04-23'  # 漏洞公布时间
    desc = '''
    SQL 注入漏洞是发生于应用程式与资料库层的安全漏洞。简而言之，
    是在输入的字串之中夹带SQL指令，在设计不良的程式当中忽略了字
    元检查，那么这些夹带进去的恶意指令就会被资料库伺服器误认为是
    正常的SQL指令而执行，因此遭到破坏或是入侵。
    '''  # 漏洞描述
    ref = 'https://zh.wikipedia.org/wiki/SQL%E8%B3%87%E6%96%99%E9%9A%B1%E7%A2%BC%E6%94%BB%E6%93%8A'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Unknown'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本
