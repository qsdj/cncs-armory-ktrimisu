# encoding: utf-8


def set_dict_value_with_schema_check(d, k, v, schema, desc=''):
    typ = schema.get('type', 'string')
    if desc != '':
        desc = desc + '-'
    if typ == 'string':
        d[k] = str(v)
    elif typ == 'boolean':
        try:
            d[k] = bool(v)
        except:
            raise Exception(
                '{}属性 {} 定义为 bool, 但是值为 {}'.format(desc, k, v))
    elif typ == 'number':
        try:
            d[k] = int(v)
        except:
            try:
                d[k] = float(v)
            except:
                raise Exception(
                    '{}属性 {} 定义为 number, 但是值为 {}'.format(desc, k, v))
    else:
        raise Exception('{}定义错误：属性 {} 类型 {} 无效'.format(desc, k, typ))
