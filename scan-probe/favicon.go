package probe

import (
	"context"
	"encoding/base64"
	"io"
	"math/bits"
	"net/http"
	"strings"
)

// faviconSignatures maps the Shodan/Fofa favicon hash (signed int32) to a product name.
//
// Hash algorithm (matches Shodan / Fofa standard):
//   1. Fetch /favicon.ico raw bytes
//   2. base64-encode with newline ('\n') every 76 chars (matches Python base64.encodebytes)
//   3. Apply MurmurHash3-32 with seed 0
//   4. Interpret the uint32 result as int32 (signed)
//
// Sources: public Shodan/Fofa favicon hash databases, community CTF writeups, manual verification.
var faviconSignatures = map[int32]string{
	// ── CMS ─────────────────────────────────────────────────────────────
	-1555081138: "WordPress",
	708682105:   "Drupal",
	-1380107629: "Joomla",

	// ── Java Middleware ──────────────────────────────────────────────────
	-1216177511: "Apache Tomcat",
	-1204866521: "Oracle WebLogic",
	-349388098:  "JBoss/WildFly",
	-1074124449: "Apache ActiveMQ",
	423677935:   "Swagger UI",
	116323821:   "Apache Shiro",

	// ── DevOps / Collaboration ───────────────────────────────────────────
	81586312:    "Jenkins",
	1278050729:  "GitLab",
	-1502345736: "Atlassian Confluence",
	1606117273:  "Atlassian Jira",
	-1647305842: "SonarQube",
	-526281708:  "Nexus Repository",
	-1433476782: "Harbor",
	1906940552:  "Gogs",
	1697532889:  "Gitea",

	// ── Monitoring ───────────────────────────────────────────────────────
	-1996397627: "Kibana",
	-1328512553: "Grafana",
	2027245011:  "Grafana (v8+)",
	-1427245498: "Zabbix",
	1432415737:  "Nagios",

	// ── Database UI ──────────────────────────────────────────────────────
	908701701:   "phpMyAdmin",
	-1654056248: "Adminer",

	// ── Storage / Infra ──────────────────────────────────────────────────
	-1427289573: "MinIO",
	271552766:   "Portainer",
	1946629440:  "Rancher",

	// ── Auth / SSO ────────────────────────────────────────────────────────
	-1416741060: "Keycloak",

	// ── Messaging ────────────────────────────────────────────────────────
	1372952010:  "RabbitMQ Management",
	-1052505694: "Rocket.Chat",
	-440515503:  "Mattermost",

	// ── Data / Analytics ─────────────────────────────────────────────────
	-1506606615: "Jupyter Notebook",
	-1614250168: "Metabase",

	// ── Network / Security ───────────────────────────────────────────────
	1296930955:  "Palo Alto PAN-OS",
	-1880762604: "Fortinet FortiGate",
	-1219049680: "Consul",
	505927315:   "Vault (HashiCorp)",

	// ── Config / Scheduling ──────────────────────────────────────────────
	-615083467:  "Nacos",
	-1360556048: "XXL-JOB",

	// ── BI ────────────────────────────────────────────────────────────────
	-1124801256: "Apache Superset",

	// ── OA / ERP (Chinese) ───────────────────────────────────────────────
	-1389752949: "致远OA",
	706414218:   "泛微OA",
	-1565372554: "通达OA",
	1574659659:  "蓝凌OA",
	-584954543:  "金蝶 Kingdee",
	1805905956:  "用友NC",

	// ── CI/CD ────────────────────────────────────────────────────────────
	-1409125547: "TeamCity",
	-1842305717: "Bamboo",
	-1671084966: "ArgoCD",
	1765546356:  "DroneCI",
	1906078566:  "GoCD",

	// ── Auth / IAM ───────────────────────────────────────────────────────
	-2005037798: "Keycloak (new)",
	703767145:   "Okta",
	-887606268:  "Microsoft ADFS",
	-1705099335: "PingFederate",

	// ── Network Devices ──────────────────────────────────────────────────
	-1632570016: "Palo Alto PAN-OS (newer)",
	-1498878492: "SonicWall",
	1616707797:  "WatchGuard Firebox",
	-703696444:  "Juniper Networks",
	-880285905:  "H3C iMC",
	1006041970:  "Sangfor SSL VPN",

	// ── Container / Orchestration ────────────────────────────────────────
	-1596144414: "KubeSphere",
	-1742111626: "OpenShift",
	-1065764236: "AWX",

	// ── API Gateway ──────────────────────────────────────────────────────
	-1452783638: "Kong Gateway",
	1533625829:  "Traefik",
	-304547130:  "Apache APISIX",

	// ── Monitoring / SIEM ────────────────────────────────────────────────
	-2088208056: "Alertmanager",
	-1073928804: "Apache SkyWalking",
	1817879508:  "Splunk",
	-1943674526: "Graylog",
	1067614854:  "Sentry",

	// ── Storage / Collab ─────────────────────────────────────────────────
	-1477767517: "Nextcloud",
	-1264658083: "Owncloud",
	1348512897:  "Seafile",
	-1026572837: "MinIO Console (v3)",

	// ── 国产 OA / ERP 扩展 ───────────────────────────────────────────────
	-1189167085: "泛微 e-cology",
	1723738089:  "泛微 e-office",
	-1420328584: "致远 A8",
	842419153:   "通达 OA (new)",
	-1048909799: "蓝凌 EKP",
	-1671577195: "用友 U8 Cloud",
	1046499268:  "金蝶 K/3 Cloud",
	-1960885652: "金蝶 EAS",
	-732723977:  "用友 NC Cloud",
	1231793682:  "正方软件 OA",
	-1886872740: "亿赛通 OA",

	// ── BI / 报表 ────────────────────────────────────────────────────────
	-1523743716: "帆软 FineReport",
	1384917879:  "帆软 FineBI",
	-1248282208: "Redash",
	-1736695009: "Apache Superset (v2)",
	-1505801428: "Metabase (new)",
	-1614199116: "Smartbi",

	// ── 安防 / 监控 ──────────────────────────────────────────────────────
	-1614079098: "海康威视 IVMS",
	1454466799:  "大华 DSS",
	-935428174:  "宇视 NetEye",
	-806068733:  "天地伟业 CCTV",
	1499660259:  "雄迈 XMEye",

	// ── 国内安全设备 ─────────────────────────────────────────────────────
	-1404695432: "天融信 NGFW",
	-619780069:  "安恒 AiDOS",
	-1503895272: "深信服 SSL VPN",
	1527633285:  "深信服 EDR",
	-1244498876: "启明星辰 天清汉马",
	1072139512:  "绿盟 IPS",
	-869489680:  "腾讯 T-SEC",
	-1773665023: "360 安全卫士企业版",
	1345042196:  "科来网络分析",
	-1268261776: "亚信安全 Deep Security",

	// ── 低代码 / 自动化 ──────────────────────────────────────────────────
	-1093421009: "Appsmith",
	-790396959:  "Tooljet",
	916066665:   "Budibase",
	-1591834088: "n8n",
	-1019022606: "Node-RED",

	// ── API 网关 ─────────────────────────────────────────────────────────
	-675839524:  "WSO2 API Manager",
	-1313513462: "Gravitee APIM",
	-1060396497: "Hasura GraphQL Engine",
	-1247697042: "Tyk API Gateway",

	// ── 容器 / K8s 相关 ──────────────────────────────────────────────────
	-1599041536: "Weave Scope",
	1278527657:  "Dozzle",
	-1516625668: "Argo CD (v2)",
	-1843528701: "Argo Workflows",
	-1349063552: "KubeSphere (new)",

	// ── IoT / 工控 ───────────────────────────────────────────────────────
	-1581543498: "EMQX Dashboard",
	1291782024:  "OpenWrt LuCI",
	-1001009215: "Mikrotik Winbox",
	-1764543019: "群晖 DSM",
	1207609549:  "威联通 QTS",

	// ── 身份认证 ─────────────────────────────────────────────────────────
	-1037272503: "Authentik",
	-905028553:  "Authelia",
	-1467993660: "Casdoor",
	-1283040688: "Zitadel",
	-1619013720: "Teleport",

	// ── CDN / 反代 ───────────────────────────────────────────────────────
	1535379938:  "Caddy",
	-856514128:  "HAProxy Stats",
	-1540303988: "Nginx Unit",
	-1016861668: "Varnish Cache Stats",
}

// probeFavicon fetches /favicon.ico and returns the Shodan/Fofa hash and matched product.
// Returns empty string for product if no signature matches.
// client 由调用方传入，避免每次调用重建 Transport 分配大量连接池和 TLS 配置。
// 若需要更短超时，调用方可通过 context.WithTimeout 限制，无需新建 client。
func probeFavicon(ctx context.Context, client *http.Client, baseURL string) (hash int32, product string) {
	faviconURL := strings.TrimRight(baseURL, "/") + "/favicon.ico"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if err != nil || len(data) == 0 {
		return 0, ""
	}
	h := faviconHash(data)
	if p := faviconSignatures[h]; p != "" {
		return h, p
	}
	// 查 EHole faviconhash 规则表（从 data/ehole_raw.json 加载）
	fpLoad()
	if eholeHashSigs != nil {
		if p := eholeHashSigs[h]; p != "" {
			return h, p
		}
	}
	return h, ""
}

// faviconHash computes the Shodan/Fofa favicon hash:
//
//	base64(raw bytes) with newline every 76 chars → MurmurHash3-32(seed=0) as signed int32
func faviconHash(data []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(encoded) + len(encoded)/76 + 2)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	return int32(murmur3_32([]byte(sb.String()), 0))
}

// murmur3_32 is a pure-Go implementation of MurmurHash3 (32-bit).
func murmur3_32(b []byte, seed uint32) uint32 {
	const (
		c1 = uint32(0xcc9e2d51)
		c2 = uint32(0x1b873593)
	)
	h := seed
	nblocks := len(b) / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(b[i*4]) | uint32(b[i*4+1])<<8 | uint32(b[i*4+2])<<16 | uint32(b[i*4+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := b[nblocks*4:]
	var k uint32
	switch len(tail) & 3 {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(b))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
