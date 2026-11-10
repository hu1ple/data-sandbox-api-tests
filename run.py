"""Run cases for the 2026-10-27 interface delivery. Python 3.10+, no third-party dependencies."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from json import JSONDecodeError, dumps, loads
from pathlib import Path
import re
import sys

import auth_sandbox
import operations
import approvals
import data_exports
import confirmed
from catalog import SCRIPTS
from core import Blocked, Context, Failure, base_url

ROOT = Path(__file__).resolve().parent
CATALOG = loads((ROOT / 'cases.json').read_text(encoding='utf-8'))
PROFILE = 'delivery-20261027'
WAITING = {
    'TC-01-03': ('人工验证','真实前端网络记录或代理需能让当前 CSRF Token 失效。'),
    'TC-04-03': ('人工验证','两份同角色不同权限点的浏览器会话需要联调代理或环境配置。'),
    'TC-12-09': ('待确认','G-18 尚未给出五个写接口缺少幂等键的统一执行口径。'),
    'TC-27-06': ('待联调','G-12 涉及清理触发、审批跳过状态及实际导出水印。'),
    'TC-33-01': ('人工验证','在交付版真实模式的上传页面查看提示并记录网络请求。'),
    'TC-33-02': ('待联调','DATA06–DATA08 未冻结，缺上传及完成的可执行契约。'),
    'TC-41-02': ('待联调','缺下载消费地址、凭证 TTL 及失效应答口径。'),
    'TC-41-03': ('待联调','缺内容审核触发入口和下载消费契约。'),
}
# Preflight required follow-up reads before permitting writes on a partial deployment.
FOLLOW_UP = {
    'TC-01-01': (2,4), 'TC-01-02': (26,27), 'TC-02-01': (4,),
    'TC-02-02': (4,), 'TC-02-03': (4,), 'TC-03-01': (4,), 'TC-05-01': (2,4),
    'TC-05-05': (4,), 'TC-11-01': (10,), 'TC-12-01': (4,10,29),
    'TC-12-02': (9,29), 'TC-12-03': (9,29), 'TC-12-04': (9,29),
    'TC-12-05': (9,29), 'TC-12-06': (9,29), 'TC-12-07': (9,29),
    'TC-12-08': (9,29), 'TC-12-10': (9,29),
    'TC-13-01': (11,), 'TC-13-02': (11,), 'TC-13-03': (11,),
    'TC-13-04': (11,), 'TC-13-05': (11,),
    'TC-15-01': (14,16,29), 'TC-15-02': (14,16), 'TC-15-03': (16,),
    'TC-17-01': (4,14,20), 'TC-17-02': (14,), 'TC-17-03': (14,), 'TC-17-04': (14,),
    'TC-19-01': (18,), 'TC-20-02': (21,), 'TC-22-01': (4,20,21), 'TC-22-02': (21,),
    'TC-25-01': (4,20,24), 'TC-25-02': (24,), 'TC-25-03': (23,24),
    'TC-27-01': (4,20,26), 'TC-27-02': (26,), 'TC-27-03': (26,),
    'TC-27-04': (26,), 'TC-27-05': (26,),
    'TC-29-03': (30,), 'TC-30-01': (6,29,34), 'TC-30-02': (6,29,34),
    'TC-30-03': (6,10,11,12,29), 'TC-30-04': (10,12,29),
    'TC-30-05': (14,15,16,29), 'TC-30-06': (14,15,16,29),
    'TC-30-07': (6,29,34), 'TC-30-08': (6,29,34), 'TC-30-09': (6,29,34),
    'TC-30-10': (6,29,34), 'TC-30-11': (29,), 'TC-30-13': (4,29),
    'TC-30-14': (6,10,11,12,13,29,34), 'TC-30-15': (4,14,15,16,17,20,29),
    'TC-34-01': (6,29), 'TC-34-02': (29,32), 'TC-34-03': (6,29),
    'TC-34-04': (6,29), 'TC-34-05': (6,29), 'TC-34-06': (6,29),
    'TC-34-07': (6,29), 'TC-34-08': (29,), 'TC-34-09': (6,29),
    'TC-35-02': (37,), 'TC-36-01': (35,37), 'TC-36-02': (35,37), 'TC-36-04': (35,37),
    'TC-39-01': (40,), 'TC-39-02': (38,40), 'TC-39-03': (40,), 'TC-39-04': (40,),
    'TC-41-01': (4,20,40), 'TC-42-01': (40,), 'TC-43-01': (4,20,40), 'TC-43-02': (4,20,40),
    'TC-43-03': (40,), 'TC-43-04': (40,), 'TC-43-06': (40,),
}
ANONYMOUS = {'TC-04-02','TC-05-01','TC-05-02','TC-05-03','TC-05-04'}

ROUTES = []
for api in CATALOG['interfaces']:
    verb, route = api['route'].split(' ',1)
    pattern = re.sub(r'\\\{[^{}]+\\\}',r'[^/]+',re.escape(route))
    ROUTES.append((api['id'], verb, re.compile(pattern)))
META = {entry['id']:entry for entry in CATALOG['cases']}


def catalog_check():
    expected = set(META)
    implemented = set(SCRIPTS)
    manual = set(WAITING)
    if implemented & manual or expected != implemented | manual:
        raise RuntimeError(f'用例与脚本映射不一致: {sorted(expected ^ (implemented | manual))}')
    if len(CATALOG['cases']) != len(expected):
        raise RuntimeError('用例索引存在重复编号')
    if {entry['api'] for entry in META.values()} != {number for number,_,_ in ROUTES}:
        raise RuntimeError('接口与用例映射不一致')
    for _,verb,pattern in ROUTES:
        if not verb or not pattern.pattern:
            raise RuntimeError('存在空接口规则')


def category(meta):
    identifier = meta['id']
    if identifier in WAITING:
        return '业务',WAITING[identifier][0]
    script = SCRIPTS[identifier]
    if meta['g'].startswith('?'):
        return script.layer,'确认后自动'
    if meta['g'].startswith('!'):
        return script.layer,'联通后自动'
    return script.layer,'自动＋复核' if script.remainder else '自动'


def read_config(path):
    try:
        cfg = loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, JSONDecodeError) as error:
        raise Blocked(f'无法加载配置文件 {path.name}，请从 fixtures.example.json 复制并填写') from error
    if not isinstance(cfg,dict) or cfg.get('profile') != PROFILE:
        raise Blocked(f'仅支持配置 profile={PROFILE}')
    if cfg.get('environment') not in ('MOCK','REAL'):
        raise Blocked('environment 须明确填 MOCK 或 REAL')
    for name in ('fixtures','cases'):
        if not isinstance(cfg.get(name,{}),dict):
            raise Blocked(f'{name} 须为 JSON 对象')
    if any(not isinstance(value,dict) for value in cfg.get('cases',{}).values()):
        raise Blocked('cases 内每个用例的夹具须为 JSON 对象')
    ready = cfg.get('ready_interfaces')
    if ready is not None and (not isinstance(ready,list) or not all(type(n) is int and 1<=n<=43 for n in ready)):
        raise Blocked('ready_interfaces 须为 API 编号数组（1–43）或 null')
    base_url(cfg.get('base_url'))
    return cfg


def run_one(meta, config, write, configuration_issue=''):
    identifier = meta['id']
    layer, mode = category(meta)
    result = {
        'caseId':identifier,'layer':layer,'mode':mode,'apiId':f'API-{meta["api"]:02}',
        'title':meta['title'],'priority':meta['priority'],'gap':meta['g'].lstrip('?!'),
        'status':'阻塞','detail':'','evidence':[],
    }
    if identifier in WAITING:
        kind, reason = WAITING[identifier]
        result.update(status='人工验证' if kind=='人工验证' else '阻塞',detail=reason)
        return result
    if configuration_issue:
        result['detail'] = configuration_issue
        return result
    script = SCRIPTS[identifier]
    if script.writes and not write:
        result['detail'] = '含写入尝试。仅在隔离测试环境使用 --allow-write 执行'
        return result
    context = None
    try:
        context = Context(config,identifier,ROUTES)
        result['evidence'] = context.evidence
        if context.ready is not None:
            required = {meta['api'], 1, *FOLLOW_UP.get(identifier, ())}
            if identifier not in ANONYMOUS:
                required.add(2)
            missing_routes = sorted(required - set(context.ready))
            if missing_routes:
                raise Blocked('依赖接口未列入 ready_interfaces: ' + '、'.join(f'API-{n:02}' for n in missing_routes))
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
    for key,label in [('pre','前置条件'),('data','测试数据'),('steps','操作步骤'),('expect','预期结果'),('g','待确认项')]:
        if meta[key]:
            print(f'{label}  {meta[key].lstrip("?!") if key=="g" else meta[key]}')
    if identifier in SCRIPTS:
        script = SCRIPTS[identifier]
        print('配置字段  ' + ('、'.join(script.keys) or '无附加 JSON 夹具'))
        if script.writes:
            print('运行开关  --allow-write')
        if script.remainder:
            print('复核  '+script.remainder)
    else:
        print('运行条件  '+WAITING[identifier][1])


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
        token_client.request('GET','/me').error(401,'UNAUTHENTICATED')
    finally:
        print(dumps(context.evidence,ensure_ascii=False,indent=2))
    print(f'{config["environment"]} / {PROFILE}，匿名 CSRF 和未登录 /me 断言通过')


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
        report = {'baseline':CATALOG['baseline'],'profile':PROFILE,'environment':config.get('environment','未配置'),
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
