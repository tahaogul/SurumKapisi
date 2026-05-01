# 🎬 SürümKapısı — 10 Dakikalık Pilot Demo Senaryosu

> Bu senaryo, potansiyel müşterilere SürümKapısı'nın tüm temel özelliklerini göstermek için tasarlanmıştır.
> Tahmini süre: 10 dakika.

---

## ⏱️ Dakika 0-1: Giriş ve Problem Tanımı

**Anlatım:**
> "Hoş geldiniz! Bugün size SürümKapısı'nı tanıtacağım — yazılım tedarik zinciri güvenliği için deterministik, kurala dayalı bir Release Gate platformu."

**Gösterin:**
- Son yıllardaki supply chain saldırılarına kısa değinin (SolarWinds, Log4Shell, xz-utils)
- "Bu saldırılar bir ortak noktaya sahip: build pipeline'ında kontrol eksikliği"

---

## ⏱️ Dakika 1-2: Sistem Başlatma

```bash
# Docker Compose ile sistemi başlatın
docker compose up -d

# Logları gösterin
docker compose logs server | tail -20
```

**Gösterin:**
- PostgreSQL otomatik başlatılıyor
- Şema ve seed data otomatik yükleniyor
- Server başlıyor → http://localhost:8080

---

## ⏱️ Dakika 2-3: Web Dashboard

```
Tarayıcı: http://localhost:8080
```

**Gösterin:**
- Dashboard'da demo projeyi
- Henüz build olmadığını
- Temiz ve minimal UI

---

## ⏱️ Dakika 3-5: SBOM Üretimi ve Yükleme

```bash
# Demo npm projesi üzerinde SBOM oluştur
surumkapisi sbom --project tests/fixtures/sample-npm-project --out demo-sbom.json

# İçeriğe göz at
cat demo-sbom.json | head -50

# Güvenlik açığı verisini içe aktar
curl -X POST http://localhost:8080/api/vulnerabilities/import \
  -H "Authorization: Bearer sk-admin-token-2024" \
  -H "Content-Type: application/json" \
  -d @sample_data/vuln_bundle.json
```

**Anlatım:**
> "SürümKapısı, projenizin bağımlılıklarını tarayarak CycloneDX formatında bir SBOM üretir. NPM, Python ve Maven/Gradle desteklenir."

---

## ⏱️ Dakika 5-6: Yapı Oluşturma ve Politika Değerlendirmesi

```bash
# Build oluştur ve değerlendir
surumkapisi evaluate \
  --sbom demo-sbom.json \
  --server http://localhost:8080 \
  --token sk-admin-token-2024 \
  --project-id c0000000-0000-0000-0000-000000000001 \
  --policy .surumkapisi.yml
```

**Beklenen çıktı:** Lodash'taki kritik CVE nedeniyle **FAIL**

**Anlatım:**
> "Bakın — lodash 4.17.20'de kritik bir güvenlik açığı var. Politikamız 'block_critical_cves' kuralıyla bunu engelliyor. Pipeline DURDU."

---

## ⏱️ Dakika 6-7: İstisna (Waiver) ile Muafiyet

```bash
# Güvenlik ekibi onayıyla 30 günlük muafiyet oluştur
curl -X POST http://localhost:8080/api/exceptions \
  -H "Authorization: Bearer sk-admin-token-2024" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "c0000000-0000-0000-0000-000000000001",
    "rule_type": "block_critical_cves",
    "rule_value": "CVE-2024-1001",
    "reason": "Güvenlik ekibi tarafından onaylandı - hotfix 2 hafta içinde planlandı",
    "approved_by_role": "Security",
    "duration_days": 30
  }'

# Tekrar değerlendir
surumkapisi evaluate \
  --sbom demo-sbom.json \
  --server http://localhost:8080 \
  --token sk-admin-token-2024 \
  --project-id c0000000-0000-0000-0000-000000000001 \
  --policy .surumkapisi.yml
```

**Beklenen çıktı:** Muafiyet var → imza ve provenance eksik → hala FAIL ama CVE engeli kalktı

---

## ⏱️ Dakika 7-8: İmzalama

```bash
# SBOM dosyasını artifact olarak imzala
surumkapisi sign \
  --artifact demo-sbom.json \
  --server http://localhost:8080 \
  --token sk-admin-token-2024
```

**Anlatım:**
> "Artifact SHA256 hash'i hesaplanıyor, sunucu tarafında RSA-2048 ile imzalanıyor ve provenance kaydı oluşturuluyor."

---

## ⏱️ Dakika 8-9: Rapor ve Web UI

```bash
# HTML rapor oluştur
surumkapisi report \
  --server http://localhost:8080 \
  --token sk-admin-token-2024 \
  --format html
```

**Gösterin:**
1. HTML raporu tarayıcıda açın
2. SBOM özeti, güvenlik açıkları, lisans dağılımı, politika sonucu gösterin
3. Web UI'da build detayını gösterin → http://localhost:8080/builds/BUILD_ID
4. Denetim günlüğünü gösterin → http://localhost:8080/audit

---

## ⏱️ Dakika 9-10: CI Entegrasyonu ve Kapanış

**Gösterin:**
- `ci/gitlab-ci.yml` — GitLab CI entegrasyonu
- `ci/github-actions.yml` — GitHub Actions entegrasyonu
- `ci/Jenkinsfile` — Jenkins entegrasyonu

**Anlatım:**
> "SürümKapısı herhangi bir CI/CD pipeline'ına 5 satır YAML ile entegre olur. Gate FAIL olduğunda pipeline otomatik durur."

**Kapanış:**
> "SürümKapısı ile:
> ✅ Her build'de otomatik SBOM
> ✅ Deterministik politika kontrolü
> ✅ Kriptografik imzalama
> ✅ Tam iz kayıtlı denetim günlüğü
> ✅ Time-bound exception yönetimi
> ✅ Tek komutla CI entegrasyonu"

---

## ❓ Beklenen Sorular ve Cevaplar

| Soru | Cevap |
|------|-------|
| On-premise çalışır mı? | Evet, tamamen kendi sunucunuzda çalışır. Dış bağımlılık yok. |
| Air-gapped ortam? | Çevrimdışı güvenlik açığı bundle'ları ile çalışır. |
| Sigstore desteği? | Mimari hazır; plug-in olarak eklenecek. |
| Mevcut SBOM araçları ile? | Harici SBOM'ları API üzerinden yükleyebilirsiniz. |
| Çoklu proje? | Multi-tenant mimari; organizasyon/proje hiyerarşisi mevcut. |
