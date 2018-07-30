# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import hashlib
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Discuz_0026'  # 平台漏洞编号，留空
    name = 'Discuz! /static/image/common/flvplayer.swf 跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2016-05-12'  # 漏洞公布时间
    desc = '''
        Discuz! x3.0 /static/image/common/flvplayer.swf 跨站脚本漏洞。
    '''  # 漏洞描述
    ref = 'http://www.discuz.net/thread-3612752-1-1.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'x3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9aa22bac-4259-414a-8291-e8f54e9e60bf'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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
            flash_md5 = "7d675405ff7c94fa899784b7ccae68d3"
            file_path = "/static/image/common/flvplayer.swf"

            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = '{target}'.format(target=self.target)+file_path
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            md5_value = hashlib.md5(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
