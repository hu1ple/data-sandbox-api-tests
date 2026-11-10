"""HTTP transport, contract assertions and fixture loading for the delivery profile."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from json import JSONDecodeError, dumps, loads
from os import environ
from threading import Barrier
from time import monotonic, sleep
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener
from uuid import uuid4
import re

AUTO = object()
EMPTY = object()
ADMIN = {
    'approval:read', 'approval:decide', 'result:approve', 'audit:read',
    'integration:manage', 'settings:manage',
}
ANALYST = {'sandbox:read', 'sandbox:create', 'sandbox:cancel', 'data:use', 'result:export'}
SETTINGS = ('retentionDays', 'exportApprovalRequired', 'defaultSandboxDays', 'watermarkEnabled')


class Blocked(Exception):
    """A required environment, account, capability or fixture is absent."""


class Failure(Exception):
    """An observed result does not match the contract."""


def check(condition, message):
    if not condition:
        raise Failure(message)


def field(obj, name, kind, *, nullable=False):
    check(isinstance(obj, dict) and name in obj, f'响应缺少 {name}')
    value = obj[name]
    if nullable and value is None:
        return value
    kinds = kind if isinstance(kind, tuple) else (kind,)
    check(type(value) in kinds, f'{name} 类型与契约不符')
    if kind is str:
        check(bool(value.strip()), f'{name} 为空')
    return value


def utc(obj, name, *, nullable=False):
    value = field(obj, name, str, nullable=nullable)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise Failure(f'{name} 不是 ISO 8601 时间') from None
    check(parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed),
          f'{name} 不是 UTC 时间')
    return parsed


def enum(obj, name, values):
    value = field(obj, name, str)
    check(value in values, f'{name} 未返回契约允许的值')
    return value


def equal(actual, expected, label):
    check(actual == expected, f'{label} 与预期不一致')


def subset(obj, expected, label='响应'):
    for key, value in expected.items():
        check(isinstance(obj, dict) and key in obj and obj[key] == value, f'{label}的 {key} 与预置值不一致')


def id_segment(value):
    check(isinstance(value, str) and bool(value.strip()) and value not in ('.', '..'),
          '路径 ID 须为有效的非空字符串')
    return quote(value, safe='')


def unique():
    return str(uuid4())


def row(items, field_name, target):
    matched = [item for item in items if item.get(field_name) == target]
    equal(len(matched), 1, f'{field_name} 匹配记录数')
    return matched[0]


def absent(items, field_name, target):
    check(all(item.get(field_name) != target for item in items), f'仍能查到 {field_name} 对应记录')


def snapshot_ids(items, field_name='id'):
    return sorted(field(item, field_name, str) for item in items)


def forbid_fields(obj, names, label):
    if isinstance(obj, list):
        for item in obj:
            forbid_fields(item, names, label)
    if isinstance(obj, dict):
        for key, value in obj.items():
            check(re.sub(r'[^a-z0-9]', '', key.lower()) not in names, f'{label}返回了敏感字段')
            forbid_fields(value, names, label)


@dataclass
class Response:
    status: int
    body: object
    raw: bytes

    @property
    def request_id(self):
        value = self.body.get('requestId') if isinstance(self.body, dict) else None
        return value if isinstance(value, str) else None

    @property
    def code(self):
        value = self.body.get('code') if isinstance(self.body, dict) else None
        return value if isinstance(value, str) else None

    def success(self, kind=dict):
        equal(self.status, 200, 'HTTP 状态')
        field(self.body, 'requestId', str)
        return field(self.body, 'data', kind)

    def empty_success(self):
        if self.status == 204:
            check(not self.raw, '204 响应含响应体')
        else:
            equal(self.status, 200, '空数据写操作的 HTTP 状态')
            if self.raw:
                field(self.body, 'requestId', str)
                check('data' in self.body and self.body['data'] in (None, {}),
                      '空数据写操作返回了额外业务数据')

    def error(self, status, code=None):
        allowed = (status,) if isinstance(status, int) else status
        check(self.status in allowed, f'HTTP {self.status}，预期 {allowed}')
        observed = field(self.body, 'code', str)
        if code is not None:
            allowed_codes = (code,) if isinstance(code, str) else code
            check(observed in allowed_codes, f'业务码与预期 {allowed_codes} 不符')
        message = field(self.body, 'message', str)
        check(re.search(r'[\u3400-\u9fff]', message), '错误 message 未包含中文')
        field(self.body, 'requestId', str)
        check('data' not in self.body, '错误体不应包含成功响应 data')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def base_url(value):
    if not isinstance(value, str):
        raise Blocked('请在配置填写 base_url')
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        raise Blocked('base_url 的主机或端口无效') from None
    if (parsed.scheme not in ('https', 'http') or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise Blocked('base_url 应为测试 API 地址，不含账号、查询参数或片段')
    if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise Blocked('远端测试 API 地址须使用 HTTPS')
    if not parsed.path.rstrip('/').endswith('/api/v1'):
        raise Blocked('base_url 须包含 /api/v1')
    return value.rstrip('/')


class Client:
    def __init__(self, context):
        self.context = context
        self.cookies = CookieJar()
        self.opener = build_opener(NoRedirect(), HTTPCookieProcessor(self.cookies))
        self.token = None

    def csrf(self, refresh=False):
        if refresh or self.token is None:
            self.token = field(self.request('GET', '/auth/csrf').success(), 'csrfToken', str)
        return self.token

    def request(self, method, path, *, query=None, body=EMPTY, csrf=AUTO, key=None, cookie=None):
        self.context.require_route(method, path)
        if not path.startswith('/') or path.startswith('//') or '?' in path or '#' in path:
            raise Failure('请求路径须是 API 内部相对路径')
        url = self.context.base + path
        if query:
            url += '?' + urlencode(query, doseq=True)
        headers = {'Accept': 'application/json'}
        if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            value = self.csrf() if csrf is AUTO else csrf
            if value is not None:
                headers['X-CSRF-Token'] = value
        if key is not None:
            headers['Idempotency-Key'] = key
        if cookie is not None:
            headers['Cookie'] = cookie
        encoded = None
        if body is not EMPTY:
            headers['Content-Type'] = 'application/json; charset=utf-8'
            encoded = dumps(body, ensure_ascii=False).encode('utf-8')
        request = Request(url, data=encoded, headers=headers, method=method)
        try:
            try:
                handle = self.opener.open(request, timeout=self.context.timeout)
            except HTTPError as error:
                handle = error
            with handle:
                status = handle.getcode()
                raw = handle.read(8_000_001)
        except (URLError, TimeoutError, OSError) as error:
            self.context.evidence.append({'method': method, 'path': path, 'transport': type(error).__name__})
            raise Blocked('请求未得到可用 HTTP 响应，请检查测试服务连接或超时') from None
        check(len(raw) <= 8_000_000, '响应超过脚本读取上限')
        try:
            parsed = loads(raw) if raw else None
        except (JSONDecodeError, UnicodeError):
            parsed = None
        response = Response(status, parsed, raw)
        self.context.evidence.append({
            'method': method, 'path': path, 'http': status,
            'code': response.code, 'requestId': response.request_id,
        })
        return response

    def login(self, username, password):
        data = self.request('POST', '/auth/dev-login',
                            body={'username': username, 'password': password}).success()
        self.token = None
        return data

    def export_cookie(self):
        request = Request(self.context.base + '/me')
        self.cookies.add_cookie_header(request)
        value = request.get_header('Cookie')
        check(bool(value), '未获得会话 Cookie')
        return value


class Context:
    def __init__(self, config, case_id, routes):
        self.config = config
        self.case_id = case_id
        self.base = base_url(config.get('base_url'))
        self.timeout = float(config.get('timeout_seconds', 20))
        self.wait = float(config.get('poll_timeout_seconds', 45))
        self.interval = float(config.get('poll_interval_seconds', 2))
        if min(self.timeout, self.wait, self.interval) <= 0:
            raise Blocked('请求超时和轮询配置须为正数')
        self.evidence = []
        self.clients = {}
        self.routes = routes
        self.ready = config.get('ready_interfaces')
        self.values = {**config.get('fixtures', {}), **config.get('cases', {}).get(case_id, {})}

    def require_route(self, method, path):
        for api, verb, pattern in self.routes:
            if method == verb and pattern.fullmatch(path):
                if self.ready is not None and api not in self.ready:
                    raise Blocked(f'依赖接口 API-{api:02} 未列入 ready_interfaces')
                return
        raise Blocked(f'{method} {path} 超出已登记的交付契约')

    def fixture(self, key):
        value = self.values.get(key)
        if value is None or value == '' or value == [] or value == {}:
            raise Blocked(f'缺少测试夹具 {key}，请在 fixtures 或 cases.{self.case_id} 配置')
        return deepcopy(value)

    def many(self, key, count):
        values = self.fixture(key)
        if not isinstance(values, list) or len(values) < count:
            raise Blocked(f'{key} 至少需要 {count} 个独立夹具')
        return values[:count]

    def credentials(self, role):
        username = environ.get(f'SANDBOX_QA_{role}_USER')
        password = environ.get(f'SANDBOX_QA_{role}_PASSWORD')
        if not username or not password:
            raise Blocked(f'缺少角色 {role} 的登录环境变量')
        return username, password

    def client(self, role='A', *, fresh=False):
        if role is None:
            return Client(self)
        if fresh or role not in self.clients:
            credentials = self.credentials(role)
            client = Client(self)
            client.login(*credentials)
            if not fresh:
                self.clients[role] = client
            return client
        return self.clients[role]

    def send(self, method, path, *, role='A', **kwargs):
        return self.client(role).request(method, path, **kwargs)

    def get(self, path, *, role='A', **kwargs):
        return self.send('GET', path, role=role, **kwargs).success()

    def array(self, path, *, role='A'):
        data = self.send('GET', path, role=role).success(list)
        check(all(isinstance(item, dict) for item in data), 'data 数组中存在非对象')
        return data

    def page(self, path, *, role='A', query=None):
        data = self.get(path, role=role, query=query)
        return page_result(data, query)

    def all(self, path, *, role='A', query=None):
        params = {**(query or {}), 'page': 1, 'pageSize': 20}
        first = self.page(path, role=role, query=params)
        items = list(first['items'])
        total = first['total']
        if total > 400:
            raise Blocked('筛选结果超过 400 条，需使用更小的独立测试范围')
        for number in range(2, (total + first['pageSize'] - 1) // first['pageSize'] + 1):
            params['page'] = number
            next_page = self.page(path, role=role, query=params)
            equal(next_page['total'], total, '分页查询 total')
            items.extend(next_page['items'])
        equal(len(items), total, '实际分页记录数')
        return items

    def poll(self, read, predicate, label):
        deadline = monotonic() + self.wait
        while True:
            value = read()
            if predicate(value):
                return value
            if monotonic() >= deadline:
                raise Failure(f'等待{label}超出配置的轮询时限')
            sleep(self.interval)

    def parallel(self, calls):
        barrier = Barrier(len(calls))

        def start(call):
            barrier.wait(timeout=self.timeout)
            return call()

        with ThreadPoolExecutor(max_workers=len(calls)) as pool:
            pending = [pool.submit(start, call) for call in calls]
            return [job.result() for job in pending]

    @contextmanager
    def saved_settings(self):
        before = settings(self.get('/settings', role='M'))
        baseline = {k: before[k] for k in SETTINGS}
        try:
            yield baseline
        finally:
            after = settings(self.get('/settings', role='M'))
            if any(after[k] != baseline[k] for k in SETTINGS):
                restored = self.send('PUT', '/settings', role='M', body=baseline).success()
                subset(restored, baseline, '还原配置')
                subset(self.get('/settings', role='M'), baseline, '配置还原后回读')


def page_result(data, query=None):
    items = field(data, 'items', list)
    check(all(isinstance(item, dict) for item in items), '分页 items 中存在非对象')
    page = field(data, 'page', int)
    size = field(data, 'pageSize', int)
    total = field(data, 'total', int)
    check(page >= 1 and size >= 1 and total >= 0 and len(items) <= min(size, total), '分页数字不一致')
    for k, v in (query or {}).items():
        if k in ('page', 'pageSize'):
            equal(data[k], v, k)
    return data


def settings(data):
    for k in SETTINGS:
        field(data, k, int if k in ('retentionDays', 'defaultSandboxDays') else bool)
    utc(data, 'updatedAt')
    return data
