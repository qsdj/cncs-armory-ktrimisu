# coding: utf-8

from CScanPoc.lib.core.enums import ProductType

PRODUCT_TYPE = {
    '74cms': ProductType.cms,
    '08cms': ProductType.cms
}

__warned = {}


def get_product_type(product_name):
    '''根据产品名获取产品类型，默认 ProductType.others'''
    result = PRODUCT_TYPE.get(product_name, ProductType.others)

    if result is ProductType.others and not __warned.has_key(product_name):
        __warned[product_name] = True
        print ('产品 {0} 未指定类型，将使用 others 类型，'
               '你可以在 CScanPoc.lib.constants.PRODUCT_TYPE 中指定'
               ).format(product_name)
    return result
