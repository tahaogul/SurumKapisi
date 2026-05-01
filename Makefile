.PHONY: all build test run docker-up docker-down clean lint fmt help

# Default
all: test build

# ---- Build ----
build: build-server build-agent

build-server:
	@echo "🔨 Server build ediliyor..."
	go build -ldflags="-s -w" -o bin/surumkapisi-server ./cmd/server

build-agent:
	@echo "🔨 Agent build ediliyor..."
	go build -ldflags="-s -w" -o bin/surumkapisi ./cmd/agent

# ---- Test ----
test:
	@echo "🧪 Testler çalıştırılıyor..."
	go test -v -race -cover -count=1 ./...

test-unit:
	@echo "🧪 Unit testler..."
	go test -v -race -cover ./internal/policy/ ./internal/sbom/ ./internal/signing/

test-cover:
	@echo "📊 Coverage raporu oluşturuluyor..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ coverage.html oluşturuldu"

# ---- Run ----
run:
	go run ./cmd/server

run-agent:
	go run ./cmd/agent

# ---- Code Quality ----
lint:
	@echo "🔍 Lint kontrolleri..."
	go vet ./...
	@echo "✅ Lint tamamlandı"

fmt:
	@echo "📝 Kod formatlama..."
	gofmt -w -s .
	@echo "✅ Formatlama tamamlandı"

# ---- Docker ----
docker-up:
	@echo "🐳 Docker Compose başlatılıyor..."
	docker compose up --build -d
	@echo "✅ http://localhost:8080"

docker-down:
	docker compose down

docker-prod:
	@echo "🐳 Production ortamı başlatılıyor..."
	docker compose -f docker-compose.prod.yml up --build -d
	@echo "✅ http://localhost (Nginx reverse proxy)"

docker-logs:
	docker compose logs -f server

docker-test:
	@echo "🧪 Docker ile testler..."
	docker compose run --rm server go test -v ./...

# ---- Database ----
db-reset:
	@echo "🗄️ Veritabanı sıfırlanıyor..."
	docker compose exec postgres psql -U skuser -d surumkapisi -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	docker compose exec postgres psql -U skuser -d surumkapisi -f /docker-entrypoint-initdb.d/001_schema.sql
	docker compose exec postgres psql -U skuser -d surumkapisi -f /docker-entrypoint-initdb.d/002_seed_data.sql
	@echo "✅ Veritabanı sıfırlandı"

db-psql:
	docker compose exec postgres psql -U skuser -d surumkapisi

# ---- Demo ----
demo: docker-up
	@echo "⏳ Sunucu başlaması bekleniyor..."
	@sleep 5
	@echo ""
	@echo "📦 Güvenlik açığı verisi yükleniyor..."
	curl -s -X POST http://localhost:8080/api/vulnerabilities/import \
		-H "Authorization: Bearer sk-admin-token-2024" \
		-H "Content-Type: application/json" \
		-d @sample_data/vuln_bundle.json | head -c 200
	@echo ""
	@echo ""
	@echo "📦 NPM projesi için SBOM oluşturuluyor..."
	bin/surumkapisi sbom --project tests/fixtures/sample-npm-project --out demo-sbom.json 2>/dev/null || true
	@echo ""
	@echo "✅ Demo hazır: http://localhost:8080"

# ---- Clean ----
clean:
	rm -rf bin/ keys/ coverage.out coverage.html
	rm -f sbom.json demo-sbom.json .surumkapisi-build-id report-*

# ---- Help ----
help:
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║   🔐 SürümKapısı — Build & Run Komutları    ║"
	@echo "╠══════════════════════════════════════════════╣"
	@echo "║  make build        → İkili dosyaları build  ║"
	@echo "║  make test         → Testleri çalıştır      ║"
	@echo "║  make test-cover   → Coverage raporu         ║"
	@echo "║  make run          → Sunucuyu başlat         ║"
	@echo "║  make docker-up    → Docker ile başlat       ║"
	@echo "║  make docker-prod  → Production ile başlat   ║"
	@echo "║  make docker-down  → Docker'ı durdur         ║"
	@echo "║  make db-reset     → Veritabanını sıfırla    ║"
	@echo "║  make demo         → Demo ortamı kur         ║"
	@echo "║  make clean        → Temizle                 ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
