# 🔐 SürümKapısı — Yazılım Tedarik Zinciri Güvenlik Platformu

**SürümKapısı**, yazılım projelerinizin sürüm süreçlerini güvenli hale getiren, deterministik kurallarla çalışan bir Release Gate platformudur.

> **AI/ML kullanmaz.** Tüm kararlar deterministik politika kurallarına dayalıdır.

---

## 🚀 Hızlı Başlangıç

### Gereksinimler
- Docker & Docker Compose
- Go 1.22+ (geliştirme için)

### 3 Adımda Çalıştırma

```bash
# 1. Projeyi klonlayın
cd surumkapisi

# 2. Docker Compose ile başlatın
docker compose up --build

# 3. Tarayıcıda açın
open http://localhost:8080
```

**Varsayılan API Token:** `sk-admin-token-2024`

---

## 📁 Proje Yapısı

```
surumkapisi/
├── cmd/
│   ├── agent/main.go          # CLI ajanı (sbom, evaluate, sign, report)
│   └── server/main.go         # API sunucusu + Web UI
├── internal/
│   ├── api/handler.go         # REST API endpoint'leri
│   ├── audit/audit.go         # Hash-zincirli denetim günlüğü
│   ├── database/database.go   # PostgreSQL bağlantı yönetimi
│   ├── models/models.go       # Veri modelleri (17 entity)
│   ├── policy/engine.go       # Deterministik politika motoru
│   ├── policy/engine_test.go  # Politika motoru testleri (12 test)
│   ├── sbom/generator.go      # SBOM üretici (NPM/Pip/Maven/Gradle)
│   ├── signing/signing.go     # RSA imzalama/doğrulama
│   └── store/store.go         # Veritabanı CRUD işlemleri
├── web/templates/             # HTML şablonları (dashboard, builds, detay, audit)
├── migrations/                # PostgreSQL şema + seed data
├── ci/                        # CI pipeline örnekleri (GitLab, GitHub Actions, Jenkins)
├── sample_data/               # Örnek güvenlik açığı verisi
├── tests/fixtures/            # Test veri dosyaları (npm/pip/maven projeleri)
├── docs/                      # Ek dokümantasyon
├── docker-compose.yml         # Docker Compose yapılandırması
├── Dockerfile.server          # Sunucu Docker imajı
├── Dockerfile.agent           # CLI Docker imajı
├── Makefile                   # Build/test/deploy komutları
├── .surumkapisi.yml           # Örnek politika dosyası
└── README.md                  # Bu dosya
```

---

## 🔧 Yapılandırma

### Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|----------|------------|----------|
| `SK_DB_HOST` | `localhost` | PostgreSQL host |
| `SK_DB_PORT` | `5432` | PostgreSQL port |
| `SK_DB_NAME` | `surumkapisi` | Veritabanı adı |
| `SK_DB_USER` | `skuser` | Veritabanı kullanıcısı |
| `SK_DB_PASSWORD` | `skpass123` | Veritabanı şifresi |
| `SK_DB_SSLMODE` | `disable` | SSL modu |
| `SK_ADMIN_TOKEN` | `sk-admin-token-2024` | API yetkilendirme token'ı |
| `SK_LISTEN_ADDR` | `:8080` | Sunucu dinleme adresi |
| `SK_SIGNING_KEY_PATH` | `./keys` | İmzalama anahtarı dizini |

---

## 📡 API Referansı

### Kimlik Doğrulama
Tüm API isteklerinde `Authorization: Bearer <TOKEN>` header'ı gereklidir.

### Endpoint'ler

| Metod | Yol | Açıklama |
|-------|-----|----------|
| `POST` | `/api/projects` | Yeni proje oluştur |
| `GET` | `/api/projects` | Projeleri listele |
| `POST` | `/api/builds` | Yeni yapı kaydı oluştur |
| `POST` | `/api/sboms` | SBOM yükle |
| `POST` | `/api/evaluate` | Politika değerlendir |
| `POST` | `/api/sign` | Artifact imzala |
| `GET` | `/api/reports/{buildId}` | Rapor al (JSON) |
| `GET` | `/api/reports/{buildId}/html` | Rapor al (HTML) |
| `GET` | `/api/audit?projectId=...` | Denetim günlüğü |
| `POST` | `/api/exceptions` | İstisna/muafiyet oluştur |
| `POST` | `/api/vulnerabilities/import` | Güvenlik açığı verisi içe aktar |

### Örnek Kullanımlar

**Proje oluştur:**
```bash
curl -X POST http://localhost:8080/api/projects \
  -H "Authorization: Bearer sk-admin-token-2024" \
  -H "Content-Type: application/json" \
  -d '{"name": "My App", "slug": "my-app", "repo_url": "https://github.com/org/app"}'
```

**Politika değerlendir:**
```bash
curl -X POST http://localhost:8080/api/evaluate \
  -H "Authorization: Bearer sk-admin-token-2024" \
  -H "Content-Type: application/json" \
  -d '{"build_id": "BUILD_ID_HERE"}'
```

---

## 🛡️ Politika DSL

Politika dosyası `.surumkapisi.yml` olarak projenizin kök dizinine yerleştirilir.

### Desteklenen Kural Tipleri

| Kural | Açıklama |
|-------|----------|
| `block_critical_cves` | Belirli önem seviyesindeki CVE'leri engeller |
| `block_forbidden_licenses` | Yasaklı lisansları engeller (GPL, AGPL vb.) |
| `require_sbom` | SBOM varlığını zorunlu kılar |
| `require_signature` | Artifact imzasını zorunlu kılar |
| `require_provenance` | Provenance alanlarını zorunlu kılar |

### Örnek Politika

```yaml
version: "1"
rules:
  - type: block_critical_cves
    enabled: true
    severity_threshold: critical

  - type: block_forbidden_licenses
    enabled: true
    licenses:
      - GPL-3.0-only
      - AGPL-3.0-only

  - type: require_sbom
    enabled: true

  - type: require_signature
    enabled: true

  - type: require_provenance
    enabled: true
    fields:
      - git_commit
      - build_time
      - sbom_hash
```

---

## 💻 CLI Kullanımı

### SBOM Oluştur
```bash
surumkapisi sbom --project ./my-app --out sbom.json
surumkapisi sbom --project ./my-app --out sbom-spdx.json --format spdx
```

### Politika Değerlendir
```bash
surumkapisi evaluate \
  --sbom sbom.json \
  --server http://localhost:8080 \
  --token sk-admin-token-2024 \
  --project-id PROJECT_ID \
  --policy .surumkapisi.yml
```

### Artifact İmzala
```bash
surumkapisi sign \
  --artifact dist/app.jar \
  --server http://localhost:8080 \
  --token sk-admin-token-2024 \
  --build-id BUILD_ID
```

### Rapor Al
```bash
surumkapisi report \
  --build BUILD_ID \
  --server http://localhost:8080 \
  --token sk-admin-token-2024 \
  --format html
```

---

## 📦 Desteklenen Ekosistemler

| Ekosistem | Kaynak Dosya | PURL Formatı |
|-----------|-------------|--------------|
| NPM (Node.js) | `package-lock.json`, `npm-shrinkwrap.json` | `pkg:npm/name@version` |
| Python (PyPI) | `requirements.txt`, `poetry.lock` | `pkg:pypi/name@version` |
| Maven | `pom.xml` | `pkg:maven/group/artifact@version` |
| Gradle | `gradle.lockfile` | `pkg:maven/group/artifact@version` |

---

## 🔐 Güvenlik Notları

1. **Üretim ortamında `SK_ADMIN_TOKEN` değerini mutlaka değiştirin.**
2. **İmzalama anahtarları:** MVP'de RSA-2048 anahtar çifti dosya sisteminde saklanır. Üretim için Vault veya HSM entegrasyonu önerilir.
3. **Denetim günlüğü:** `audit_events` tablosu append-only'dir. PostgreSQL trigger'ı UPDATE/DELETE işlemlerini engeller.
4. **Hash zinciri:** Her denetim olayı bir önceki olayın hash'ini içerir. Zincir kırılması manipülasyon göstergesidir.
5. **OIDC/LDAP:** MVP token tabanlı auth kullanır. Üretim OIDC entegrasyonu planlanmıştır.

---

## 🧪 Testler

```bash
# Tüm testleri çalıştır
go test -v ./...

# Sadece politika motoru testleri
go test -v ./internal/policy/

# Docker ile
docker compose run --rm server go test ./...
```

---

## 🚀 Üretime Geçiş (Kubernetes)

MVP Docker Compose üzerinde çalışır. Üretim için:

1. **Helm Chart:** `charts/surumkapisi/` altında oluşturulacak
2. **PostgreSQL:** Managed servis (RDS, Cloud SQL) kullanın
3. **Ingress:** TLS ile Nginx/Traefik
4. **Signing:** Sigstore/Cosign entegrasyonu
5. **Auth:** OIDC provider (Keycloak, Auth0)
6. **Monitoring:** Prometheus + Grafana

---

## 📋 Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| DB bağlantı hatası | `SK_DB_HOST` ve PostgreSQL servisinin çalıştığını kontrol edin |
| 401 Unauthorized | `Authorization: Bearer TOKEN` header'ını kontrol edin |
| SBOM boş | Projenizde desteklenen lockfile olduğundan emin olun |
| İmza hatası | `./keys/` dizininin yazılabilir olduğunu kontrol edin |
| Template hatası | `web/templates/` dizininin mevcut olduğunu kontrol edin |

---

## 📄 Lisans

Bu proje özel lisans altındadır. Ticari kullanım için iletişime geçin.

**© 2024 SürümKapısı**
