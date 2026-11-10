"""Data requests, ingestions, datasets, results and export scripts."""
from catalog import case
from core import check, enum, equal, field, forbid_fields, id_segment as s, row, snapshot_ids, subset, unique, utc

SOURCE_SECRET_KEYS = {
    'connectionstring','connectionurl','connectionuri','connstr','dsn','jdbcurl','username',
    'account','password','passwd','secret','secretkey','accesskey','credentials','token','apikey',
}


@case('TC-31-01', needs='resource_keyword resource_samples')
def resource_directory(c):
    query = {'keyword':c.fixture('resource_keyword')}
    entries = c.fixture('resource_samples')
    pages = [c.page('/data-resources',query={**query,'page':n,'pageSize':1}) for n in (1,2)]
    check(not set(snapshot_ids(pages[0]['items'])) & set(snapshot_ids(pages[1]['items'])),'资源分页重复')
    equal(pages[0]['total'],len(entries),'目录总数')
    items = c.all('/data-resources',query=query)
    equal(snapshot_ids(items),snapshot_ids(entries),'授权资源集合')
    for expected in entries:
        data = row(items,'id',expected['id'])
        subset(data,expected)
        field(data,'name',str)
        enum(data,'authorizationStatus',{'GRANTED','REVOKED','EXPIRED'})
        utc(data,'authorizationExpiresAt',nullable=True)
        field(data,'allowedActions',list)
    data = c.page('/data-resources',query={'keyword':unique()})
    equal((data['items'],data['total']),([],0),'空资源页')


def string_values(obj):
    if isinstance(obj,str):
        yield obj
    elif isinstance(obj,list):
        for item in obj:
            yield from string_values(item)
    elif isinstance(obj,dict):
        for value in obj.values():
            yield from string_values(value)


@case('TC-32-01', layer='业务', needs='source_samples',
      remainder='浏览器复查 DISCONNECTED 可见但禁用。可用 SANDBOX_QA_SOURCE_SENTINELS（用换行分隔）核对服务端合成凭据值。')
def source_directory(c):
    from os import environ
    response = c.send('GET','/data-sources')
    items = field(response.success(),'items',list)
    samples = c.fixture('source_samples')
    equal({item['status'] for item in samples},{'CONNECTED','DEGRADED','DISCONNECTED'},'数据源状态夹具')
    for expected in samples:
        actual = row(items,'id',expected['id'])
        subset(actual,expected)
        for key in ('id','name','description'):
            field(actual,key,str)
        enum(actual,'type',{'BUSINESS_DB','DATA_WAREHOUSE','FILE_SERVER','OBJECT_STORAGE'})
    forbid_fields(response.body,SOURCE_SECRET_KEYS,'数据源目录')
    secrets = [v for v in environ.get('SANDBOX_QA_SOURCE_SENTINELS','').splitlines() if v.strip()]
    observed = list(string_values(response.body))
    for value in secrets:
        check(not any(value in text for text in observed),'数据源目录泄露测试凭据值')


def ingestion(c, target, filters):
    return row(c.all('/ingestions',query=filters),'id',target)


def dataset_query(c, env, **filters):
    return c.all('/ingest/data',query={**filters,'environmentId':env})


def ingestion_ready(c, target, env, expected_count):
    item = c.poll(lambda:ingestion(c,target,{'environmentId':env}),lambda x:x['status']=='READY','入箱 READY')
    subset(item,{'environmentId':env,'rowCount':expected_count})
    matches = [x for x in dataset_query(c,env) if x.get('sourceIngestionId')==target]
    equal(len(matches),1,'同一批次数据集数')
    subset(matches[0],{'environmentId':env,'sourceIngestionId':target})
    return matches[0]


def retry_ingestion(c, target, client=None):
    current = client or c.client()
    return current.request('POST','/ingestions/'+s(target)+'/retry')


@case('TC-36-01', layer='业务', writes=True, needs='ingestion_retry_fixture',
      remainder='接口核对批次行数与数据集唯一性。数据集内容和重复行需通过下游数据核对。')
def retry_failed_ingestion(c):
    fixture = c.fixture('ingestion_retry_fixture')
    target,env = fixture['ingestionId'],fixture['environmentId']
    before = ingestion(c,target,{'environmentId':env})
    equal(before['status'],'FAILED','重试前批次状态')
    check('RETRY' in before['allowedActions'],'失败批次没有 RETRY')
    reply = retry_ingestion(c,target).success()
    subset(reply,{'id':target,'status':'QUEUED','progressPercent':0},'重试受理')
    ingestion_ready(c,target,env,fixture['rowCount'])


@case('TC-36-02', layer='业务', writes=True, needs='ingestion_no_retry_fixtures')
def cannot_retry_ingestion(c):
    for fixture,expected in zip(c.many('ingestion_no_retry_fixtures',3),('READY','CANCELED','FAILED')):
        target,env = fixture['ingestionId'],fixture['environmentId']
        filters = {'environmentId':env}
        original = ingestion(c,target,filters)
        equal(original['status'],expected,'批次夹具状态')
        if expected=='FAILED':
            check('RETRY' not in original['allowedActions'],'该失败夹具不得有 RETRY')
        before = snapshot_ids(dataset_query(c,env))
        retry_ingestion(c,target).error((400,403,409,422))
        equal(ingestion(c,target,filters),original,'原批次')
        equal(snapshot_ids(dataset_query(c,env)),before,'拒绝后数据集')


@case('TC-36-03', writes=True)
def missing_ingestion(c):
    retry_ingestion(c,unique()).error(404,'INGESTION_NOT_FOUND')


@case('TC-36-04', layer='业务', writes=True, needs='ingestion_retry_fixture',
      remainder='接口核对批次数与数据集唯一性，重复行和下游写入次数需单独核对。')
def concurrent_ingestion(c):
    fixture = c.fixture('ingestion_retry_fixture')
    target,env = fixture['ingestionId'],fixture['environmentId']
    original = ingestion(c,target,{'environmentId':env})
    equal(original['status'],'FAILED','并发前批次')
    check('RETRY' in original['allowedActions'],'失败批次没有 RETRY')
    clients = [c.client('A',fresh=True) for _ in range(2)]
    for client in clients:
        client.csrf()
    results = c.parallel([lambda client=client:retry_ingestion(c,target,client) for client in clients])
    check(any(r.status==200 for r in results),'两个并发请求均未受理')
    for reply in results:
        if reply.status==200:
            equal(reply.success()['id'],target,'重试返回批次')
        else:
            reply.error((400,409,422))
    ingestion_ready(c,target,env,fixture['rowCount'])


def exports(c, *, role='A', **filters):
    return c.all('/exports',role=role,query=filters)


def export(c, target, *, role='A', **filters):
    return row(exports(c,role=role,**filters),'id',target)


def export_ids(c, result_id, role='A'):
    return snapshot_ids([item for item in exports(c,role=role) if item.get('resultId')==result_id])


@case('TC-39-02', layer='业务', writes=True, needs='export_body result_other')
def forbidden_export(c):
    foreign = c.fixture('result_other')
    row(c.all('/results',role='OTHER'),'id',foreign)
    before = export_ids(c,foreign,'OTHER')
    body = {**c.fixture('export_body'),'resultId':foreign}
    c.send('POST','/exports',body=body,key=unique()).error((403,404,422))
    equal(export_ids(c,foreign,'OTHER'),before,'他人结果的出箱申请')


def delivery_retry(c, target):
    return c.send('POST','/exports/'+s(target)+'/deliveries/retry')


@case('TC-42-01', layer='业务', writes=True, needs='export_failed export_delivered',
      remainder='失败夹具的回传由联调环境控制，回传次数需查下游日志。')
def retry_delivery(c):
    failed,done = c.fixture('export_failed'),c.fixture('export_delivered')
    original = export(c,failed,status='DELIVERY_FAILED')
    delivered = export(c,done,status='DELIVERED')
    delivery_retry(c,done).error((400,403,409,422))
    equal(export(c,done,status='DELIVERED'),delivered,'已交付记录')
    reply = delivery_retry(c,failed).success()
    subset(reply,{'id':failed,'status':'DELIVERING','resultId':original['resultId']})
    result = c.poll(lambda:export(c,failed),lambda x:x['status']=='DELIVERED','出箱交付完成')
    subset(result,{'resultId':original['resultId']})


@case('TC-42-02', writes=True)
def missing_delivery(c):
    delivery_retry(c,unique()).error(404,'EXPORT_NOT_FOUND')
