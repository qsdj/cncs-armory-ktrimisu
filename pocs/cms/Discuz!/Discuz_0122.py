# coding: utf-8
import hashlib
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0122'  # 平台漏洞编号，留空
    name = 'Discuz! x3.0 /static/image/common/flvplayer.swf 跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-10-09'  # 漏洞公布时间
    desc = '''
    Discuz! x3.0 /static/image/common/flvplayer.swf 跨站脚本漏洞。
    '''  # 漏洞描述
    ref = 'http://www.ipuman.com/pm6/138/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '12e76a2c-3e30-4691-95de-6d1dd9def70e'  # 平台 POC 编号，留空
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
            flash_md5 = "7d675405ff7c94fa899784b7ccae68d3"
            file_path = "/static/image/common/flvplayer.swf"
            verify_url = self.target + file_path
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            md5_value = hashlib.md5(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
