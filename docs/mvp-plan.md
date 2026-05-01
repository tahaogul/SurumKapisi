# 📋 SürümKapısı — 90 Günlük MVP Planı ve Ticari Paketleme

---

## 🗓️ 12 Haftalık Plan

### Hafta 1-2: Çekirdek Platform (MVP Core)
- [x] PostgreSQL şeması (17 tablo, indeksler, kısıtlamalar)
- [x] Go sunucu iskeleti (Gorilla Mux, REST API)
- [x] Docker Compose ortamı
- [x] Temel SBOM üretici (NPM, Python, Maven)
- [x] Deterministik politika motoru (5 kural tipi)
- **Kabul Kriteri:** `docker compose up` ile sistem ayağa kalkar, SBOM üretilir, politika değerlendirilir.

### Hafta 3-4: İmzalama, Provenance, Denetim
- [x] RSA-2048 imzalama/doğrulama
- [x] Provenance kayıt sistemi
- [x] Hash-zincirli denetim günlüğü
- [x] Exception/waiver yönetimi
- **Kabul Kriteri:** Imza oluşturulur, provenance kaydedilir, denetim zinciri bütünlüğü doğrulanır.

### Hafta 5-6: CLI Agent ve CI Entegrasyonu
- [x] CLI komutları (sbom, evaluate, sign, report)
- [x] GitLab CI, GitHub Actions, Jenkins pipeline örnekleri
- [x] Raporlama (HTML + JSON)
- **Kabul Kriteri:** Tüm CI platformlarında çalışan pipeline örnekleri hazır.

### Hafta 7-8: Web UI ve Kullanıcı Deneyimi
- [x] Dashboard, build listesi, detay sayfaları
- [x] Denetim günlüğü görüntüleyici
- [ ] Kullanıcı yönetimi (RBAC UI)
- [ ] Politika editörü (web)
- **Kabul Kriteri:** Web UI'dan tüm veriler görüntülenebilir.

### Hafta 9-10: Güvenlik Sağlamlaştırma
- [ ] OIDC/LDAP entegrasyonu
- [ ] Rate limiting ve input validation
- [ ] Gizli bilgi yönetimi (Vault entegrasyonu outline)
- [ ] Güvenlik açığı veritabanı otomatik güncelleme mekanizması
- **Kabul Kriteri:** Penetrasyon testinden geçer.

### Hafta 11-12: Üretim Hazırlığı
- [ ] Kubernetes Helm chart
- [ ] Horizontal pod autoscaling
- [ ] Prometheus metrics + Grafana dashboard
- [ ] Kapsamlı dokümantasyon
- [ ] Pilot müşteri onboarding materyalleri
- **Kabul Kriteri:** Helm ile Kubernetes'e deploy edilebilir, monitoring çalışır.

---

## 📦 Ticari Paketleme

### 🟢 Pilot Tier (Ücretsiz / 3 Aya Kadar)
| Özellik | Dahil |
|---------|-------|
| Proje sayısı | 3 |
| Build/ay | 500 |
| SBOM üretimi | ✅ |
| Politika değerlendirme | ✅ |
| İmzalama | ✅ |
| Web UI | ✅ |
| Destek | E-posta |
| **Fiyat** | **Ücretsiz** |

### 🔵 Pro Tier
| Özellik | Dahil |
|---------|-------|
| Proje sayısı | 25 |
| Build/ay | 5,000 |
| Tüm Pilot özellikleri | ✅ |
| OIDC/LDAP entegrasyonu | ✅ |
| Webhook bildirimleri | ✅ |
| API rate limit artırımı | ✅ |
| Öncelikli destek | ✅ |
| **Fiyat (USD)** | **$499/ay** |
| **Fiyat (TRY)** | **₺15,000/ay** |

### 🟣 Enterprise Tier
| Özellik | Dahil |
|---------|-------|
| Proje sayısı | Sınırsız |
| Build/ay | Sınırsız |
| Tüm Pro özellikleri | ✅ |
| On-premise kurulum | ✅ |
| Air-gapped mod | ✅ |
| Sigstore entegrasyonu | ✅ |
| Custom policy rules | ✅ |
| SLA garantisi | ✅ |
| Özel eğitim | ✅ |
| **Fiyat (USD)** | **$1,999/ay** |
| **Fiyat (TRY)** | **₺60,000/ay** |

---

## 💰 Fiyatlandırma Stratejisi

### Hedef Pazar
- **Pilot:** Startup'lar, küçük ekipler (1-10 geliştirici)
- **Pro:** Orta ölçekli şirketler (10-100 geliştirici)
- **Enterprise:** Büyük kuruluşlar, finans, sağlık, savunma sektörleri

### Gelir Tahminleri (12 Ay)
| Senaryo | Pilot | Pro | Enterprise | Aylık Gelir |
|---------|-------|-----|------------|-------------|
| Pesimist | 10 | 3 | 1 | $3,496 |
| Gerçekçi | 25 | 10 | 3 | $10,987 |
| İyimser | 50 | 25 | 10 | $32,465 |

### Upsell Stratejisi
1. **Pilot → Pro:** 3 ay ücretsiz sonrası otomatik geçiş teklifi
2. **Pro → Enterprise:** Custom rule ihtiyacı veya compliance gereksinimleri
3. **Add-on'lar:** Consulting, eğitim, custom entegrasyon

---

## 🗺️ Yol Haritası (Post-MVP)

### Q2 2024 — Platform Olgunlaştırma
- Sigstore/Cosign entegrasyonu
- SLSA Level 3 uyumluluğu
- Vulnerability feed otomasyonu (OSV, NVD)
- Grafana dashboard şablonları

### Q3 2024 — Ekosistem Genişletme
- .NET (NuGet), Ruby (Gems), Rust (Cargo) desteği
- Container image SBOM (Syft entegrasyonu)
- IaC güvenlik kuralları (Terraform, Kubernetes manifests)

### Q4 2024 — Kurumsal Özellikler
- Multi-cluster Kubernetes desteği
- Compliance raporlama (SOC2, ISO 27001)
- API gateway entegrasyonu
- White-label seçeneği
