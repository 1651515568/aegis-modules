"""Standalone script — add builtin extra fingerprints to fingers.json"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
FINGERS = os.path.join(HERE, '..', 'data', 'fingers.json')

EXTRA = [
    {"product": "禅道 ZenTao", "category": "ProjectManagement", "rules": [{"location": "body", "keywords": ["zentao"]}, {"location": "title", "keywords": ["禅道"]}]},
    {"product": "TAPD", "category": "ProjectManagement", "rules": [{"location": "body", "keywords": ["tapd.cn"]}, {"location": "title", "keywords": ["tapd"]}]},
    {"product": "蓝凌 EKP", "category": "OA", "rules": [{"location": "body", "keywords": ["ekp-web"]}, {"location": "title", "keywords": ["蓝凌ekp"]}]},
    {"product": "用友 U8 Cloud", "category": "ERP", "rules": [{"location": "body", "keywords": ["u8cloud"]}, {"location": "title", "keywords": ["用友u8"]}]},
    {"product": "金蝶 EAS", "category": "ERP", "rules": [{"location": "body", "keywords": ["kingdee.eas"]}, {"location": "title", "keywords": ["金蝶eas"]}]},
    {"product": "金蝶 K/3 Cloud", "category": "ERP", "rules": [{"location": "body", "keywords": ["k3cloud"]}, {"location": "title", "keywords": ["k3cloud"]}]},
    {"product": "正方软件 OA", "category": "OA", "rules": [{"location": "body", "keywords": ["zhengfang"]}, {"location": "title", "keywords": ["正方软件"]}]},
    {"product": "亿赛通 OA", "category": "OA", "rules": [{"location": "body", "keywords": ["esafenet"]}, {"location": "title", "keywords": ["亿赛通"]}]},
    {"product": "新中大 OA", "category": "OA", "rules": [{"location": "body", "keywords": ["newgrand"]}, {"location": "title", "keywords": ["新中大"]}]},
    {"product": "科脉 ERP", "category": "ERP", "rules": [{"location": "body", "keywords": ["kemay"]}, {"location": "title", "keywords": ["科脉"]}]},
    {"product": "APISIX Dashboard", "category": "APIGateway", "rules": [{"location": "title", "keywords": ["apisix dashboard"]}, {"location": "body", "keywords": ["apisix-dashboard"]}]},
    {"product": "WSO2 API Manager", "category": "APIGateway", "rules": [{"location": "title", "keywords": ["wso2 api manager"]}, {"location": "body", "keywords": ["wso2.apim"]}]},
    {"product": "Gravitee API Gateway", "category": "APIGateway", "rules": [{"location": "title", "keywords": ["gravitee"]}, {"location": "body", "keywords": ["gravitee.io"]}]},
    {"product": "EMQX Dashboard", "category": "IoT", "rules": [{"location": "title", "keywords": ["emqx"]}, {"location": "body", "keywords": ["emqx dashboard"]}]},
    {"product": "OpenWrt LuCI", "category": "Network", "rules": [{"location": "title", "keywords": ["luci"]}, {"location": "body", "keywords": ["openwrt"]}, {"location": "body", "keywords": ["luci-mod-status"]}]},
    {"product": "pfSense", "category": "Network", "rules": [{"location": "title", "keywords": ["pfsense"]}, {"location": "body", "keywords": ["pfsense"]}]},
    {"product": "OPNsense", "category": "Network", "rules": [{"location": "title", "keywords": ["opnsense"]}, {"location": "body", "keywords": ["opnsense"]}]},
    {"product": "Mikrotik RouterOS", "category": "Network", "rules": [{"location": "title", "keywords": ["mikrotik"]}, {"location": "body", "keywords": ["routeros"]}]},
    {"product": "Netdata", "category": "Monitoring", "rules": [{"location": "title", "keywords": ["netdata"]}, {"location": "body", "keywords": ["netdata dashboard"]}]},
    {"product": "VictoriaMetrics", "category": "Monitoring", "rules": [{"location": "title", "keywords": ["victoriametrics"]}, {"location": "body", "keywords": ["victoriametrics"]}]},
    {"product": "OpenObserve", "category": "Monitoring", "rules": [{"location": "title", "keywords": ["openobserve"]}, {"location": "body", "keywords": ["openobserve"]}]},
    {"product": "Greenplum", "category": "Database", "rules": [{"location": "title", "keywords": ["greenplum"]}, {"location": "body", "keywords": ["greenplum database"]}]},
    {"product": "StarRocks", "category": "Database", "rules": [{"location": "title", "keywords": ["starrocks"]}, {"location": "body", "keywords": ["starrocks"]}]},
    {"product": "DolphinDB", "category": "Database", "rules": [{"location": "title", "keywords": ["dolphindb"]}, {"location": "body", "keywords": ["dolphindb"]}]},
    {"product": "Databend", "category": "Database", "rules": [{"location": "title", "keywords": ["databend"]}, {"location": "body", "keywords": ["databend"]}]},
    {"product": "CockroachDB Admin UI", "category": "Database", "rules": [{"location": "title", "keywords": ["cockroachdb"]}, {"location": "body", "keywords": ["cockroach labs"]}]},
    {"product": "Dozzle", "category": "Container", "rules": [{"location": "title", "keywords": ["dozzle"]}, {"location": "body", "keywords": ["dozzle"]}]},
    {"product": "Weave Scope", "category": "Container", "rules": [{"location": "title", "keywords": ["weave scope"]}, {"location": "body", "keywords": ["weavescope"]}]},
    {"product": "Argo Workflows", "category": "Workflow", "rules": [{"location": "title", "keywords": ["argo workflows"]}, {"location": "body", "keywords": ["argo-workflows"]}]},
    {"product": "Prefect", "category": "Workflow", "rules": [{"location": "title", "keywords": ["prefect"]}, {"location": "body", "keywords": ["prefect.io"]}]},
    {"product": "Dagster", "category": "Workflow", "rules": [{"location": "title", "keywords": ["dagster"]}, {"location": "body", "keywords": ["dagster"]}]},
    {"product": "MLflow", "category": "MLOps", "rules": [{"location": "title", "keywords": ["mlflow"]}, {"location": "body", "keywords": ["mlflow"]}]},
    {"product": "Kubeflow", "category": "MLOps", "rules": [{"location": "title", "keywords": ["kubeflow"]}, {"location": "body", "keywords": ["kubeflow"]}]},
    {"product": "JupyterHub", "category": "Data", "rules": [{"location": "title", "keywords": ["jupyterhub"]}, {"location": "body", "keywords": ["jupyterhub"]}]},
    {"product": "Redash", "category": "BI", "rules": [{"location": "title", "keywords": ["redash"]}, {"location": "body", "keywords": ["redash"]}]},
    {"product": "Appsmith", "category": "LowCode", "rules": [{"location": "title", "keywords": ["appsmith"]}, {"location": "body", "keywords": ["appsmith"]}]},
    {"product": "Budibase", "category": "LowCode", "rules": [{"location": "title", "keywords": ["budibase"]}, {"location": "body", "keywords": ["budibase"]}]},
    {"product": "Tooljet", "category": "LowCode", "rules": [{"location": "title", "keywords": ["tooljet"]}, {"location": "body", "keywords": ["tooljet"]}]},
    {"product": "n8n", "category": "Automation", "rules": [{"location": "title", "keywords": ["n8n"]}, {"location": "body", "keywords": ["n8n.io"]}]},
    {"product": "Node-RED", "category": "Automation", "rules": [{"location": "title", "keywords": ["node-red"]}, {"location": "body", "keywords": ["node-red"]}]},
    {"product": "Hasura GraphQL", "category": "APIGateway", "rules": [{"location": "title", "keywords": ["hasura"]}, {"location": "body", "keywords": ["hasura graphql"]}]},
    {"product": "Casdoor", "category": "Auth", "rules": [{"location": "title", "keywords": ["casdoor"]}, {"location": "body", "keywords": ["casdoor"]}]},
    {"product": "Authentik", "category": "Auth", "rules": [{"location": "title", "keywords": ["authentik"]}, {"location": "body", "keywords": ["authentik"]}]},
    {"product": "Authelia", "category": "Auth", "rules": [{"location": "title", "keywords": ["authelia"]}, {"location": "body", "keywords": ["authelia"]}]},
    {"product": "Zitadel", "category": "Auth", "rules": [{"location": "title", "keywords": ["zitadel"]}, {"location": "body", "keywords": ["zitadel"]}]},
    {"product": "Teleport", "category": "Auth", "rules": [{"location": "title", "keywords": ["teleport"]}, {"location": "body", "keywords": ["gravitational/teleport"]}]},
    {"product": "Headscale", "category": "Network", "rules": [{"location": "title", "keywords": ["headscale"]}, {"location": "body", "keywords": ["headscale"]}]},
    {"product": "Netbird", "category": "Network", "rules": [{"location": "title", "keywords": ["netbird"]}, {"location": "body", "keywords": ["netbird"]}]},
    {"product": "Linkerd Viz", "category": "ServiceMesh", "rules": [{"location": "title", "keywords": ["linkerd"]}, {"location": "body", "keywords": ["linkerd-dashboard"]}]},
    {"product": "Consul Terraform Sync", "category": "Orchestration", "rules": [{"location": "body", "keywords": ["consul-terraform-sync"]}]},
    {"product": "泛微 e-cology", "category": "OA", "rules": [{"location": "body", "keywords": ["e-cology"]}, {"location": "title", "keywords": ["泛微"]}, {"location": "body", "keywords": ["/wui/ecology"]}]},
    {"product": "泛微 e-office", "category": "OA", "rules": [{"location": "body", "keywords": ["e-office"]}, {"location": "title", "keywords": ["e-office"]}]},
    {"product": "致远 A8 OA", "category": "OA", "rules": [{"location": "body", "keywords": ["seeyon"]}, {"location": "title", "keywords": ["致远"]}]},
    {"product": "通达 OA", "category": "OA", "rules": [{"location": "body", "keywords": ["tdnoa"]}, {"location": "title", "keywords": ["通达oa"]}, {"location": "body", "keywords": ["tongda"]}]},
    {"product": "帆软 FineReport", "category": "BI", "rules": [{"location": "title", "keywords": ["finereport"]}, {"location": "body", "keywords": ["finereport"]}, {"location": "body", "keywords": ["fanruan"]}]},
    {"product": "帆软 FineBI", "category": "BI", "rules": [{"location": "title", "keywords": ["finebi"]}, {"location": "body", "keywords": ["finebi"]}]},
    {"product": "大华 DSS", "category": "Security", "rules": [{"location": "title", "keywords": ["dss"]}, {"location": "body", "keywords": ["dahuasecurity"]}]},
    {"product": "海康威视 IVMS", "category": "Security", "rules": [{"location": "title", "keywords": ["ivms"]}, {"location": "body", "keywords": ["hikvision"]}]},
    {"product": "宇视 NetEye", "category": "Security", "rules": [{"location": "title", "keywords": ["neteye"]}, {"location": "body", "keywords": ["uniview"]}]},
    {"product": "天融信 NGFW", "category": "Security", "rules": [{"location": "title", "keywords": ["topsec"]}, {"location": "body", "keywords": ["topsec"]}]},
    {"product": "安恒 AiDOS", "category": "Security", "rules": [{"location": "body", "keywords": ["dbsec.cn"]}, {"location": "title", "keywords": ["安恒"]}]},
    {"product": "深信服 SSL VPN", "category": "VPN", "rules": [{"location": "body", "keywords": ["sangfor"]}, {"location": "title", "keywords": ["深信服"]}]},
    {"product": "用友 NC Cloud", "category": "ERP", "rules": [{"location": "body", "keywords": ["ncccloud"]}, {"location": "title", "keywords": ["nc cloud"]}]},
    {"product": "360 企业安全浏览器", "category": "Security", "rules": [{"location": "body", "keywords": ["360.cn/safe"]}, {"location": "title", "keywords": ["360安全"]}]},
    {"product": "亚信安全 Deep Security", "category": "Security", "rules": [{"location": "body", "keywords": ["aissist"]}, {"location": "title", "keywords": ["亚信安全"]}]},
    {"product": "启明星辰 天清汉马", "category": "Security", "rules": [{"location": "body", "keywords": ["venustech"]}, {"location": "title", "keywords": ["启明星辰"]}]},
]

with open(FINGERS, 'r', encoding='utf-8') as f:
    data = json.load(f)

existing_products = {e['product'].lower() for e in data}
added = 0
for entry in EXTRA:
    if entry['product'].lower() not in existing_products:
        data.append(entry)
        existing_products.add(entry['product'].lower())
        added += 1

with open(FINGERS, 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print(f'added={added}, total={len(data)}')
