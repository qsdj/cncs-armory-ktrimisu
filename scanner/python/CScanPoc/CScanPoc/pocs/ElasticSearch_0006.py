# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse

class Vuln(ABVuln):
    vuln_id = 'ElasticSearch_0006' # 平台漏洞编号，留空
    name = 'ElasticSearch 9200端口 未授权访问漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-01-20'  # 漏洞公布时间
    desc = '''
        默认情况，Elasticsearch开启后会监听9200端口可以在未授权的情况下访问，从而导致敏感信息泄漏。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'ElasticSearch'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '91af3c86-31ae-4653-8484-27acf11d5dfe'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            target = urlparse.urlparse(self.target)
            verify_url = '%s://%s:9200/_nodes/stats' % (target.scheme, target.netloc)
            try:
                content = requests.get(verify_url, timeout=5).text
            except:
                content = ''
            if 'cluster_name' in content and 'transport_address":' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
