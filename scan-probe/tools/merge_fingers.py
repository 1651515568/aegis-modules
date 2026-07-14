"""
merge_fingers.py — 合并 EHole 指纹库到 AEGIS fingers.json

用法：
    python merge_fingers.py [ehole_finger.json]

如果没有提供参数，会先尝试从网络下载 EHole 指纹库；
若网络不可达，则仅追加内置的扩展指纹条目。

输出：直接覆盖 ../data/fingers.json
"""

import json
import os
import sys
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FINGERS_PATH = os.path.join(SCRIPT_DIR, '..', 'data', 'fingers.json')
EHOLE_URL = 'https://raw.githubusercontent.com/EdgeSecurityTeam/EHole/main/finger.json'


def load_ehole(path=None):
    """加载 EHole 指纹库，返回转换后的 AEGIS productEntry 列表"""
    raw = None
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    else:
        print(f'尝试从 {EHOLE_URL} 下载 EHole 指纹库…')
        try:
            with urllib.request.urlopen(EHOLE_URL, timeout=20) as resp:
                raw = json.loads(resp.read().decode('utf-8'))
            print(f'下载成功，共 {len(raw)} 条')
        except Exception as e:
            print(f'下载失败: {e}')
            return []

    converted = []
    for item in raw:
        cms = item.get('cms') or item.get('name') or ''
        method = item.get('method', 'keyword')
        location = item.get('location', 'body')
        keyword = item.get('keyword', [])
        if isinstance(keyword, str):
            keyword = [keyword]

        # 标准化 location
        if location not in ('body', 'header', 'title', 'cookie'):
            location = 'body'

        rule = {'location': location, 'keywords': keyword}
        if method == 'faviconhash':
            # EHole favicon hash 规则无法直接转换，跳过
            continue

        converted.append({
            'product': cms,
            'category': 'EHole',
            'rules': [rule],
        })
    return converted


# ── 内置扩展指纹（50+ 条，覆盖国产 OA/ERP、API 网关、容器平台等）──────────
BUILTIN_EXTRA = [
    {"product": "禅道 ZenTao", "category": "ProjectManagement", "rules": [
        {"location": "body", "keywords": ["zentao"]},
        {"location": "title", "keywords": ["禅道"]},
        {"location": "body", "keywords": ["/zentao/"]},
    ]},
    {"product": "TAPD", "category": "ProjectManagement", "rules": [
        {"location": "body", "keywords": ["tapd.cn"]},
        {"location": "title", "keywords": ["tapd"]},
    ]},
    {"product": "蓝凌 EKP", "category": "OA", "rules": [
        {"location": "body", "keywords": ["ekp-web"]},
        {"location": "title", "keywords": ["蓝凌ekp"]},
    ]},
    {"product": "用友 U8 Cloud", "category": "ERP", "rules": [
        {"location": "body", "keywords": ["u8cloud"]},
        {"location": "title", "keywords": ["用友u8"]},
    ]},
    {"product": "金蝶 EAS", "category": "ERP", "rules": [
        {"location": "body", "keywords": ["kingdee.eas"]},
        {"location": "title", "keywords": ["金蝶eas"]},
    ]},
    {"product": "金蝶 K/3 Cloud", "category": "ERP", "rules": [
        {"location": "body", "keywords": ["k3cloud"]},
        {"location": "title", "keywords": ["k3cloud"]},
    ]},
    {"product": "正方软件 OA", "category": "OA", "rules": [
        {"location": "body", "keywords": ["zhengfang"]},
        {"location": "title", "keywords": ["正方软件"]},
    ]},
    {"product": "亿赛通 OA", "category": "OA", "rules": [
        {"location": "body", "keywords": ["esafenet"]},
        {"location": "title", "keywords": ["亿赛通"]},
    ]},
    {"product": "新中大 OA", "category": "OA", "rules": [
        {"location": "body", "keywords": ["newgrand"]},
        {"location": "title", "keywords": ["新中大"]},
    ]},
    {"product": "科脉 ERP", "category": "ERP", "rules": [
        {"location": "body", "keywords": ["kemay"]},
        {"location": "title", "keywords": ["科脉"]},
    ]},
    {"product": "APISIX Dashboard", "category": "APIGateway", "rules": [
        {"location": "title", "keywords": ["apisix dashboard"]},
        {"location": "body", "keywords": ["apisix-dashboard"]},
    ]},
    {"product": "WSO2 API Manager", "category": "APIGateway", "rules": [
        {"location": "title", "keywords": ["wso2 api manager"]},
        {"location": "body", "keywords": ["wso2.apim"]},
    ]},
    {"product": "Gravitee API Gateway", "category": "APIGateway", "rules": [
        {"location": "title", "keywords": ["gravitee"]},
        {"location": "body", "keywords": ["gravitee.io"]},
    ]},
    {"product": "EMQX Dashboard", "category": "IoT", "rules": [
        {"location": "title", "keywords": ["emqx"]},
        {"location": "body", "keywords": ["emqx dashboard"]},
    ]},
    {"product": "OpenWrt LuCI", "category": "Network", "rules": [
        {"location": "title", "keywords": ["luci"]},
        {"location": "body", "keywords": ["openwrt"]},
        {"location": "body", "keywords": ["luci-mod-status"]},
    ]},
    {"product": "pfSense", "category": "Network", "rules": [
        {"location": "title", "keywords": ["pfsense"]},
        {"location": "body", "keywords": ["pfsense"]},
    ]},
    {"product": "OPNsense", "category": "Network", "rules": [
        {"location": "title", "keywords": ["opnsense"]},
        {"location": "body", "keywords": ["opnsense"]},
    ]},
    {"product": "Mikrotik RouterOS", "category": "Network", "rules": [
        {"location": "title", "keywords": ["mikrotik"]},
        {"location": "body", "keywords": ["routeros"]},
    ]},
    {"product": "Netdata", "category": "Monitoring", "rules": [
        {"location": "title", "keywords": ["netdata"]},
        {"location": "body", "keywords": ["netdata dashboard"]},
    ]},
    {"product": "VictoriaMetrics", "category": "Monitoring", "rules": [
        {"location": "title", "keywords": ["victoriametrics"]},
        {"location": "body", "keywords": ["victoriametrics"]},
    ]},
    {"product": "Mimir", "category": "Monitoring", "rules": [
        {"location": "body", "keywords": ["grafana/mimir"]},
    ]},
    {"product": "OpenObserve", "category": "Monitoring", "rules": [
        {"location": "title", "keywords": ["openobserve"]},
        {"location": "body", "keywords": ["openobserve"]},
    ]},
    {"product": "Greenplum", "category": "Database", "rules": [
        {"location": "title", "keywords": ["greenplum"]},
        {"location": "body", "keywords": ["greenplum database"]},
    ]},
    {"product": "StarRocks", "category": "Database", "rules": [
        {"location": "title", "keywords": ["starrocks"]},
        {"location": "body", "keywords": ["starrocks"]},
    ]},
    {"product": "DolphinDB", "category": "Database", "rules": [
        {"location": "title", "keywords": ["dolphindb"]},
        {"location": "body", "keywords": ["dolphindb"]},
    ]},
    {"product": "Databend", "category": "Database", "rules": [
        {"location": "title", "keywords": ["databend"]},
        {"location": "body", "keywords": ["databend"]},
    ]},
    {"product": "CockroachDB Admin UI", "category": "Database", "rules": [
        {"location": "title", "keywords": ["cockroachdb"]},
        {"location": "body", "keywords": ["cockroach labs"]},
    ]},
    {"product": "Dozzle", "category": "Container", "rules": [
        {"location": "title", "keywords": ["dozzle"]},
        {"location": "body", "keywords": ["dozzle"]},
    ]},
    {"product": "Weave Scope", "category": "Container", "rules": [
        {"location": "title", "keywords": ["weave scope"]},
        {"location": "body", "keywords": ["weavescope"]},
    ]},
    {"product": "Argo Workflows", "category": "Workflow", "rules": [
        {"location": "title", "keywords": ["argo workflows"]},
        {"location": "body", "keywords": ["argo-workflows"]},
    ]},
    {"product": "Prefect", "category": "Workflow", "rules": [
        {"location": "title", "keywords": ["prefect"]},
        {"location": "body", "keywords": ["prefect.io"]},
    ]},
    {"product": "Dagster", "category": "Workflow", "rules": [
        {"location": "title", "keywords": ["dagster"]},
        {"location": "body", "keywords": ["dagster"]},
    ]},
    {"product": "MLflow", "category": "MLOps", "rules": [
        {"location": "title", "keywords": ["mlflow"]},
        {"location": "body", "keywords": ["mlflow"]},
    ]},
    {"product": "Kubeflow", "category": "MLOps", "rules": [
        {"location": "title", "keywords": ["kubeflow"]},
        {"location": "body", "keywords": ["kubeflow"]},
    ]},
    {"product": "JupyterHub", "category": "Data", "rules": [
        {"location": "title", "keywords": ["jupyterhub"]},
        {"location": "body", "keywords": ["jupyterhub"]},
    ]},
    {"product": "Superset (Preset)", "category": "BI", "rules": [
        {"location": "body", "keywords": ["preset.io"]},
    ]},
    {"product": "Redash", "category": "BI", "rules": [
        {"location": "title", "keywords": ["redash"]},
        {"location": "body", "keywords": ["redash"]},
    ]},
    {"product": "Appsmith", "category": "LowCode", "rules": [
        {"location": "title", "keywords": ["appsmith"]},
        {"location": "body", "keywords": ["appsmith"]},
    ]},
    {"product": "Budibase", "category": "LowCode", "rules": [
        {"location": "title", "keywords": ["budibase"]},
        {"location": "body", "keywords": ["budibase"]},
    ]},
    {"product": "Tooljet", "category": "LowCode", "rules": [
        {"location": "title", "keywords": ["tooljet"]},
        {"location": "body", "keywords": ["tooljet"]},
    ]},
    {"product": "n8n", "category": "Automation", "rules": [
        {"location": "title", "keywords": ["n8n"]},
        {"location": "body", "keywords": ["n8n.io"]},
    ]},
    {"product": "Node-RED", "category": "Automation", "rules": [
        {"location": "title", "keywords": ["node-red"]},
        {"location": "body", "keywords": ["node-red"]},
    ]},
    {"product": "Hasura GraphQL", "category": "APIGateway", "rules": [
        {"location": "title", "keywords": ["hasura"]},
        {"location": "body", "keywords": ["hasura graphql"]},
    ]},
    {"product": "PostgREST", "category": "APIGateway", "rules": [
        {"location": "header", "key": "server", "keywords": ["postgrest"]},
        {"location": "body", "keywords": ["postgrest"]},
    ]},
    {"product": "Casdoor", "category": "Auth", "rules": [
        {"location": "title", "keywords": ["casdoor"]},
        {"location": "body", "keywords": ["casdoor"]},
    ]},
    {"product": "Authentik", "category": "Auth", "rules": [
        {"location": "title", "keywords": ["authentik"]},
        {"location": "body", "keywords": ["authentik"]},
    ]},
    {"product": "Authelia", "category": "Auth", "rules": [
        {"location": "title", "keywords": ["authelia"]},
        {"location": "body", "keywords": ["authelia"]},
    ]},
    {"product": "Zitadel", "category": "Auth", "rules": [
        {"location": "title", "keywords": ["zitadel"]},
        {"location": "body", "keywords": ["zitadel"]},
    ]},
    {"product": "Teleport", "category": "Auth", "rules": [
        {"location": "title", "keywords": ["teleport"]},
        {"location": "body", "keywords": ["gravitational/teleport"]},
    ]},
    {"product": "Headscale", "category": "Network", "rules": [
        {"location": "title", "keywords": ["headscale"]},
        {"location": "body", "keywords": ["headscale"]},
    ]},
    {"product": "Netbird", "category": "Network", "rules": [
        {"location": "title", "keywords": ["netbird"]},
        {"location": "body", "keywords": ["netbird"]},
    ]},
    {"product": "Linkerd Viz", "category": "ServiceMesh", "rules": [
        {"location": "title", "keywords": ["linkerd"]},
        {"location": "body", "keywords": ["linkerd-dashboard"]},
    ]},
    {"product": "Consul Terraform Sync", "category": "Orchestration", "rules": [
        {"location": "body", "keywords": ["consul-terraform-sync"]},
    ]},
]


def merge_fingers(ehole_entries, builtin_entries, existing):
    """合并所有指纹条目，按 product 去重"""
    existing_products = {e['product'].lower() for e in existing}
    added = 0
    for entry in ehole_entries + builtin_entries:
        if entry['product'].lower() not in existing_products:
            existing.append(entry)
            existing_products.add(entry['product'].lower())
            added += 1
    return added


def main():
    ehole_path = sys.argv[1] if len(sys.argv) > 1 else None

    # 加载现有 fingers.json
    with open(FINGERS_PATH, 'r', encoding='utf-8') as f:
        existing = json.load(f)
    print(f'现有指纹数: {len(existing)}')

    # 加载 EHole 指纹
    ehole_entries = load_ehole(ehole_path)
    print(f'EHole 指纹数: {len(ehole_entries)}')

    # 合并
    added = merge_fingers(ehole_entries, BUILTIN_EXTRA, existing)
    print(f'新增指纹数: {added}，合并后总数: {len(existing)}')

    # 写回
    with open(FINGERS_PATH, 'w', encoding='utf-8') as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)
    print(f'已写入 {FINGERS_PATH}')


if __name__ == '__main__':
    main()
