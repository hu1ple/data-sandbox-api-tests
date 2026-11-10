"""Run cases for the v4 / 2026-11-10 interface delivery. Python 3.10+, no third-party dependencies."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from importlib import import_module
from json import JSONDecodeError, dumps, loads
from pathlib import Path
import re
import sys

from catalog import SCRIPTS
from core import Blocked, Context, Failure, base_url

for module in ('auth_sandbox','operations','sandbox_v4','modules_v4','data_exports','confirmed'):
    import_module(module)

ROOT = Path(__file__).resolve().parent
CATALOG = loads((ROOT / 'cases.json').read_text(encoding='utf-8'))
PROFILE = 'v4-20261110'
REFERENCE = 'b20ab05-20261110'
PROFILES = (PROFILE, REFERENCE)
WAITING = {
    'TC-01-03': '浏览器',
    'TC-04-03': '浏览器',
    'TC-27-06': '外部联调',
    'TC-V4-SBX01-02': '浏览器',
    'TC-V4-SBX01-05': '浏览器',
    'TC-V4-SBX05-02': '浏览器',
    'TC-V4-REG01-01': '浏览器',
    'TC-V4-DAT16-01': '浏览器',
    'TC-V4-EXP07-01': '待确认',
}
FOLLOW_UP = {
    'TC-02-02': 'AUTH03', 'TC-02-03': 'AUTH03',
    'TC-05-01': 'AUTH02 AUTH03', 'TC-05-05': 'AUTH03',
    'TC-20-02': 'SEC02', 'TC-22-01': 'AUTH03 SEC01 SEC02', 'TC-22-02': 'SEC02',
    'TC-25-01': 'AUTH03 SEC01', 'TC-25-03': 'INT01',
    'TC-27-01': 'AUTH03 SEC01', 'TC-36-01': 'DAT04 DAT12', 'TC-36-02': 'DAT04 DAT12',
    'TC-36-04': 'DAT04 DAT12', 'TC-39-02': 'EXP01 EXP04', 'TC-42-01': 'EXP04',
}
ANONYMOUS = {'TC-02-02','TC-02-03','TC-04-02','TC-05-01','TC-05-02','TC-05-03','TC-05-04'}

INTERFACES = {entry['id']:entry for entry in CATALOG['interfaces']}
ROUTES = []
for api in INTERFACES.values():
    for entry in api['paths']:
        pattern = re.sub(r'\\\{[^{}]+\\\}',r'[^/]+',re.escape(entry['path']))
        ROUTES.append((api['id'], entry['method'], re.compile(pattern)))
ROUTES.extend([
    ('OP01','GET',re.compile(r'/sandboxes/operations/[^/]+')),
    ('PLT03','GET',re.compile('/metrics/usage/sandboxes')),
])
META = {entry['id']:entry for entry in CATALOG['cases']}


def catalog_check():
    expected = set(META)
    implemented = set(SCRIPTS)
    manual = set(WAITING)
    if implemented & manual or expected != implemented | manual:
        raise RuntimeError(f'用例与脚本映射不一致: {sorted(expected ^ (implemented | manual))}')
    if len(CATALOG['cases']) != len(expected):
        raise RuntimeError('用例索引存在重复编号')
    if {entry['api'] for entry in META.values()} != set(INTERFACES):
        raise RuntimeError('接口与用例映射不一致')
    if any(set(script.requires)-set(INTERFACES) for script in SCRIPTS.values()):
        raise RuntimeError('脚本依赖存在未知接口编号')
    for _,verb,pattern in ROUTES:
        if not verb or not pattern.pattern:
            raise RuntimeError('存在空接口规则')


def category(meta):
    identifier = meta['id']
    if identifier in WAITING:
        return '业务','人工验证' if WAITING[identifier]=='浏览器' else '待补条件'
    script = SCRIPTS[identifier]
    modes = {'待确认':'确认后自动','待联调':'联通后自动','参考包验证':'参考包自动'}
    return script.layer,modes.get(meta['design'],'自动＋复核' if script.remainder else '自动')


def read_config(path):
    try:
        cfg = loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, JSONDecodeError) as error:
        raise Blocked(f'无法加载配置文件 {path.name}，请从 fixtures.example.json 复制并填写') from error
    if not isinstance(cfg,dict) or cfg.get('profile') not in PROFILES:
        raise Blocked(f'请选择 profile={PROFILE} 或 {REFERENCE}')
    if cfg.get('environment') not in ('MOCK','REAL'):
        raise Blocked('environment 须明确填 MOCK 或 REAL')
    if cfg.get('profile')==REFERENCE and cfg.get('environment')!='MOCK':
        raise Blocked('参考包仅用于已确认的 MOCK 部署')
    login_path=cfg.get('login_path')
    if login_path is not None and (login_path not in ('/auth/dev-login','/auth/login') or
                                   (login_path=='/auth/login' and cfg['profile']!=REFERENCE)):
        raise Blocked('账号密码登录路径与配置版本不匹配')
    if cfg.get('operation_path') not in (None,'/operations','/sandboxes/operations'):
        raise Blocked('operation_path 须为已确认的操作单路径前缀')
    confirmed=cfg.get('confirmed_cases',[])
    if not isinstance(confirmed,list) or not all(isinstance(item,str) and item in META for item in confirmed):
        raise Blocked('confirmed_cases 须填写已确认的当前用例编号数组')
    for name in ('fixtures','cases'):
        if not isinstance(cfg.get(name,{}),dict):
            raise Blocked(f'{name} 须为 JSON 对象')
    if any(not isinstance(value,dict) for value in cfg.get('cases',{}).values()):
        raise Blocked('cases 内每个用例的夹具须为 JSON 对象')
    ready = cfg.get('ready_interfaces')
    if ready is not None and (not isinstance(ready,list) or not all(isinstance(n,str) and n in INTERFACES for n in ready)):
        raise Blocked('ready_interfaces 须为接口编号数组（如 AUTH01、SBX04）或 null')
    base_url(cfg.get('base_url'))
    return cfg


def run_one(meta, config, write, configuration_issue=''):
    identifier = meta['id']
    layer, mode = category(meta)
    result = {
        'caseId':identifier,'layer':layer,'mode':mode,'apiId':meta['api'],
        'title':meta['title'],'priority':meta['priority'],'design':meta['design'],'gap':meta['g'],
        'status':'阻塞','detail':'','evidence':[],
    }
    if identifier in WAITING:
        kind = WAITING[identifier]
        result.update(status='人工验证' if kind=='浏览器' else '阻塞',
                      detail=f'{kind}场景，使用 --show 查看执行步骤和待确认项')
        return result
    if configuration_issue:
        result['detail'] = configuration_issue
        return result
    script = SCRIPTS[identifier]
    if meta['design']=='参考包验证' and config.get('profile')!=REFERENCE:
        result['detail']='仅适用于已确认的 b20ab05 参考包 MOCK'
        return result
    if meta['design'] in ('待确认','待联调') and identifier not in config.get('confirmed_cases',[]):
        result['detail']='确认契约或联调条件后，将用例加入 confirmed_cases'
        return result
    if script.writes and not write:
        result['detail'] = '含写入尝试。仅在隔离测试环境使用 --allow-write 执行'
        return result
    context = None
    try:
        context = Context(config,identifier,ROUTES)
        result['evidence'] = context.evidence
        if context.ready is not None:
            required = {meta['api'], *script.requires, *FOLLOW_UP.get(identifier,'').split()}
            if script.authenticated and identifier not in ANONYMOUS:
                required.update(('AUTH01',context.login_api))
            if script.writes or identifier in {'TC-02-02','TC-02-03','TC-V4-AUTH02-01','TC-V4-AUTH05-01'}:
                required.add('AUTH01')
            missing_routes = sorted(required - set(context.ready))
            if missing_routes:
                raise Blocked('依赖接口未列入 ready_interfaces: ' + '、'.join(missing_routes))
        missing = [name for name in script.keys if context.values.get(name) in (None,'',[],{})]
        if missing:
            raise Blocked('缺少夹具 ' + '、'.join(missing))
        script.execute(context)
    except Blocked as exc:
        result.update(status='阻塞',detail=str(exc))
    except Failure as exc:
        result.update(status='失败',detail=str(exc))
    except (ValueError,TypeError,KeyError,IndexError):
        result.update(status='脚本或数据错误',detail='检查夹具的 JSON 结构、输入字段与接口响应形态。')
    except Exception as exc:
        result.update(status='脚本或数据错误',detail=f'执行未完成（{type(exc).__name__}）。')
    else:
        if script.remainder:
            result.update(status='需复核',detail=script.remainder)
        else:
            result.update(status='通过',detail='本脚本断言通过')
    return result


def show(meta):
    identifier = meta['id']
    layer, mode = category(meta)
    print(f'{identifier}  {meta["title"]}  {meta["priority"]}  {layer} / {mode}')
    print(f'关联接口  {meta["api"]}  {meta["route"]}')
    for key,label in [('pre','前置条件'),('data','测试数据'),('steps','操作步骤'),('expect','预期结果'),('design','设计状态'),('g','待确认项')]:
        if meta[key]:
            print(f'{label}  {meta[key].lstrip("?!") if key=="g" else meta[key]}')
    if identifier in SCRIPTS:
        script = SCRIPTS[identifier]
        follow_up = (*script.requires,*FOLLOW_UP.get(identifier,'').split())
        if follow_up:
            print('回查依赖  '+'、'.join(dict.fromkeys(follow_up)))
        print('配置字段  ' + ('、'.join(script.keys) or '无附加 JSON 夹具'))
        if script.writes:
            print('运行开关  --allow-write')
        if script.remainder:
            print('复核  '+script.remainder)
    else:
        print('运行条件  '+WAITING[identifier])


def fixture_template(selected):
    sample = loads((ROOT / 'fixtures.example.json').read_text(encoding='utf-8'))
    sample['cases'] = {
        entry['id']:{key:None for key in SCRIPTS[entry['id']].keys}
        for entry in selected if entry['id'] in SCRIPTS and SCRIPTS[entry['id']].keys
    }
    return sample


def probe(config):
    context = Context(config,'环境检查',ROUTES)
    token_client = context.client(None)
    try:
        token_client.csrf()
        token_client.request('GET','/me').error(401)
    finally:
        print(dumps(context.evidence,ensure_ascii=False,indent=2))
    print(f'{config["environment"]} / {config["profile"]}，匿名 CSRF 和未登录 /me 断言通过')


def print_summary(selected=None):
    entries = list(META.values()) if selected is None else selected
    counts = Counter(category(meta)[1] for meta in entries)
    print(f'{len(entries)} 条用例 | ' + ' | '.join(f'{mode} {counts[mode]}' for mode in sorted(counts)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--list',action='store_true',help='列出用例及脚本形态')
    group.add_argument('--show',action='store_true',help='显示选中用例的执行步骤和夹具字段')
    group.add_argument('--fixture-template',action='store_true',help='把选中用例的配置草稿输出为 JSON')
    group.add_argument('--probe',action='store_true',help='只检查匿名 CSRF 和未登录 /me')
    group.add_argument('--self-test',action='store_true',help='使用本地模拟 HTTP 验证脚本工具本身')
    parser.add_argument('--case',action='append',metavar='ID',help='编号或通配符。可多次指定')
    parser.add_argument('--layer',choices=('contract','business'),help='只选择契约或业务规则脚本')
    parser.add_argument('--config',type=Path)
    parser.add_argument('--allow-write',action='store_true',help='仅对隔离测试环境启用写入及写入拒绝测试')
    parser.add_argument('--report',type=Path,help='保存 JSON 执行记录')
    args = parser.parse_args(argv)
    catalog_check()
    if args.self_test:
        from self_test import run_self_test
        return run_self_test()
    wanted = {'contract':'契约','business':'业务'}.get(args.layer)
    selected = [meta for identifier,meta in META.items()
                if (not args.case or any(fnmatchcase(identifier,p.upper()) for p in args.case))
                and (wanted is None or category(meta)[0]==wanted)]
    if not selected:
        parser.error('选择范围内没有用例')
    if args.list or (not any([args.show,args.fixture_template,args.probe,args.case,args.layer,args.report,args.allow_write])
                     and args.config is None):
        for meta in selected:
            layer,mode = category(meta)
            print(f'{meta["id"]} {meta["priority"]} {layer} / {mode} {meta["title"]}')
        print_summary(selected)
        return 0
    if args.show:
        for meta in selected:
            show(meta)
            print()
        return 0
    if args.fixture_template:
        print(dumps(fixture_template(selected),ensure_ascii=False,indent=2))
        return 0
    issue = ''
    try:
        config = read_config(args.config or ROOT/'fixtures.local.json')
        if args.probe:
            probe(config)
            return 0
    except (Blocked,Failure) as exc:
        if args.probe:
            print(f'环境检查未完成  {exc}')
            return 2
        config = {}
        issue = str(exc)
    if args.report and args.report.exists():
        print('报告文件已存在。请指定新的路径以保留上次记录。')
        return 2
    results = [run_one(meta,config,args.allow_write,issue) for meta in selected]
    for result in results:
        print(f'{result["caseId"]}  {result["status"]}  {result["title"]}  {result["detail"]}')
    counts = dict(Counter(result['status'] for result in results))
    if args.report:
        report = {'baseline':CATALOG['baseline'],'profile':config.get('profile','未配置'),'environment':config.get('environment','未配置'),
                  'recordedAt':datetime.now(timezone.utc).isoformat(),'counts':counts,'cases':results}
        args.report.parent.mkdir(parents=True,exist_ok=True)
        try:
            with args.report.open('x',encoding='utf-8') as output:
                output.write(dumps(report,ensure_ascii=False,indent=2)+'\n')
        except FileExistsError:
            print('报告文件已存在。请指定新的路径以保留上次记录。')
            return 2
    print('  '.join(f'{name} {value}' for name,value in counts.items()))
    if any(result['status'] in ('失败','脚本或数据错误') for result in results):
        return 1
    if any(result['status']!='通过' for result in results):
        return 2
    return 0


if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    raise SystemExit(main())
