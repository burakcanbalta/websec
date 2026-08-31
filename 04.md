<img width="1024" height="595" alt="idor" src="https://github.com/user-attachments/assets/beb5f124-9082-4c83-b003-8d3a52fff0ed" />

**IDOR (Insecure Direct Object Reference)**, bir web uygulamasının kullanıcıdan gelen bir kimlik/parametre değerine (ID, referans, dosya yolu vb.) dayanarak veri veya işlem sunarken, bu değere erişim yetkisini **doğru şekilde doğrulamaması** sonucu ortaya çıkan kritik bir yetkilendirme (authorization) açığıdır.

Bu açık sayesinde saldırgan:

* Başka kullanıcılara ait verilere erişebilir
* Başka kullanıcılar adına işlem yapabilir (güncelleme, silme)
* Yetkisiz şekilde ayrıcalık yükseltebilir (privilege escalation)
* Kurumsal (B2B/SaaS) ortamlarda farklı müşterilere (tenant) ait verilere sızabilir

IDOR, **OWASP Top 10**'da "Broken Access Control" kategorisinin en yaygın ve en sık rastlanan alt türlerinden biridir. SQL Injection veya XSS'in aksine IDOR genellikle **sözdizimsel bir hata değil, mantıksal bir eksikliktir** — kod "çalışır", sorgu "doğru sonucu döner", ama kimin bu sonucu görmeye yetkili olduğu hiç sorgulanmamıştır. Bu yüzden WAF'lar, statik analiz araçları ve otomatik tarayıcılar IDOR'u genellikle kaçırır; bulmak çoğu zaman **iş mantığını anlamayı** gerektirir.

---

## IDOR Gerçek Hayatta Nerelerde Çıkar?

Yeni başlayanların en çok sorduğu soru şudur:

> "Tamam anladım ama ben bunu nerede görürüm?"

Cevap net:

**Bir ID, referans veya kimlik ile veri/işlem döndüren her yer potansiyel hedeftir.**

En sık görülen alanlar:

* Profil / hesap detay sayfaları (`?user_id=123`)
* Fatura, sipariş, PDF/rapor indirme uç noktaları (`/invoice/8842`)
* API endpoint'leri (`/api/v1/orders/{id}`)
* Mesajlaşma / bildirim sistemleri (`/messages/{id}`)
* Dosya yükleme/indirme sistemleri (`/files/{uuid}`)
* Şifre sıfırlama / hesap doğrulama akışları (token tabanlı)
* Admin panelleri ve çoklu rol yapıları
* B2B SaaS ürünlerinde tenant/organizasyon bazlı veriler

Kısaca:
**Kullanıcıdan bir referans alınıyor ve o referansa göre veri dönülüyorsa, IDOR ihtimali vardır.**

---

## IDOR Nasıl Çalışır?

Tipik bir profil görüntüleme isteği:

```
GET /api/v1/users/1044/profile
Authorization: Bearer <kullanici_A_token>
```

Sorun şudur:

> **Backend, `1044` değerinin gerçekten istek sahibine ait olup olmadığını kontrol etmeden veriyi döner.**

Saldırgan (kullanıcı A) sadece ID'yi değiştirir:

```
GET /api/v1/users/1045/profile
Authorization: Bearer <kullanici_A_token>
```

Uygulama şunu ayırt edemez:

> "Bu token'ın sahibi gerçekten 1045 numaralı kullanıcı mı?"

Sonuç: **Yatay yetki atlatma (Horizontal Privilege Escalation)** — kullanıcı A, kendi seviyesinde başka bir kullanıcının (B) verisine erişir.

Eğer erişilen veri normal bir kullanıcıdan değil de **daha yüksek yetkili bir hesaptan** (örn. admin) ise buna **Dikey Yetki Atlatma (Vertical Privilege Escalation)** denir.

---

## IDOR Türleri

### 1. Klasik Sıralı ID (Sequential ID) IDOR

En temel ve en kolay tespit edilen türdür.

```
/invoice/1001
/invoice/1002
/invoice/1003 ...
```

* ID'ler artan sayısaldır
* Saldırgan sadece sayıyı değiştirerek tüm kayıtları tarayabilir
* Otomasyonla (Burp Intruder, basit script) kolayca exploit edilir

```python
for i in range(1000, 2000):
    r = requests.get(f"https://target.com/invoice/{i}", headers=headers)
    if r.status_code == 200:
        print(f"Erişildi: {i}")
```

---

### 2. Parametre Tabanlı IDOR (GET/POST/JSON Body)

ID her zaman URL'de olmak zorunda değildir — request body, header veya cookie içinde de gelebilir.

```json
POST /api/v1/order/cancel
{
  "order_id": 55231
}
```

`order_id` değeri istek sahibine ait değilse, sunucu yine de işlemi gerçekleştirebilir. Bu, GET tabanlı IDOR'lara göre daha kolay atlanır çünkü loglarda ve tarayıcı geçmişinde daha az görünür durur.

---

### 3. Fonksiyonel (İşlemsel) IDOR

Sadece veri okuma değil, **yazma/silme/güncelleme** işlemlerinde de ortaya çıkar — genellikle çok daha yıkıcıdır.

```
PUT /api/v1/messages/9931
{ "content": "değiştirilmiş mesaj" }
```

```
DELETE /api/v1/documents/4471
```

Okuma tabanlı IDOR "veri sızıntısı"dır; işlemsel IDOR ise **veri bütünlüğünü** doğrudan tehdit eder.

---

### 4. UUID/GUID Tabanlı IDOR

Geliştiriciler genellikle "UUID tahmin edilemez, o yüzden yetki kontrolüne gerek yok" varsayımıyla hareket eder. Bu varsayım her zaman doğru değildir.

**UUIDv1 zafiyeti:** UUIDv1, zaman damgası ve MAC adresi bileşenlerinden türetilir. Belirli bir zaman aralığında oluşturulmuş kayıtlar biliniyorsa, UUID uzayı ciddi şekilde daraltılıp brute-force edilebilir hale gelir.

**Sızıntı yoluyla UUID elde etme:** UUID'ler çoğu zaman "tahmin edilmez" diye korunmaz, ama şu yollarla sızabilir:

* Hata mesajları (stack trace, debug response)
* Herkese açık profil/paylaşım linkleri
* API'nin liste (`GET /api/v1/documents`) uç noktasında yetki kontrolü olmadan tüm UUID'lerin dönmesi
* E-posta bildirimleri, PDF export'ları, sitemap.xml gibi ikincil kanallar

```
GET /api/v1/documents?limit=1000
```

Bu istek eğer yetki filtresi olmadan tüm kullanıcıların belge UUID'lerini dönerse, "tahmin edilemez ID" savunması tamamen anlamsız hale gelir — çünkü saldırganın tahmin etmesine gerek kalmaz, ID kendisine servis edilmiştir.

---

### 5. Kriptografik / Hash'lenmiş ID IDOR

Bazı sistemler ID'yi doğrudan göstermek yerine hash'ler veya şifreler:

```
/download?ref=8f14e45fceea167a5a36dedd4bea2543
```

Bu, `MD5(1044)` gibi basit bir hash olabilir. Sorunlar:

* Zayıf hash algoritmaları (MD5, SHA1 tuzsuz) rainbow table ile kırılabilir
* Aynı ID her zaman aynı hash'i ürettiği için, düşük ID aralığı (1–10000) kolayca hash'lenip karşılaştırılabilir
* "Obscurity" (gizlilik ile güvenlik) gerçek bir yetki kontrolünün yerine geçmez

```python
import hashlib
for i in range(1, 10000):
    h = hashlib.md5(str(i).encode()).hexdigest()
    if h == "8f14e45fceea167a5a36dedd4bea2543":
        print("Gerçek ID bulundu:", i)
```

---

### 6. JWT Tabanlı IDOR

Bazı uygulamalarda yetki kontrolü, URL'deki ID yerine JWT içindeki claim'e dayanır. Bu tasarım doğru olsa da, JWT'nin kendisi zayıfsa IDOR'a dönüşür.

**Örnek zafiyetli JWT payload'ı:**

```json
{
  "user_id": 1044,
  "role": "user"
}
```

Saldırı yüzeyleri:

* **`alg: none` saldırısı:** Sunucu imza doğrulamasını atlıyorsa, saldırgan header'ı `{"alg":"none"}` yapıp claim'i değiştirip imzasız token gönderebilir.
* **Zayıf secret brute-force:** HS256 imzalı token'larda zayıf bir secret (`123456`, `secret`) kullanılıyorsa `hashcat` veya `jwt_tool` ile kırılabilir.
* **Algoritma karışıklığı (RS256 → HS256):** Sunucu RS256 bekliyorsa ama HS256'yı da kabul ediyorsa, saldırgan public key'i HMAC secret'ı olarak kullanıp geçerli görünen sahte token üretebilir.

```bash
python3 jwt_tool.py <token> -C -d rockyou.txt
```

Token kırıldığında veya imza atlatıldığında, saldırgan `user_id` claim'ini istediği değere çevirip sunucunun kendisine güvenmesini sağlar — bu klasik IDOR'un JWT üzerinden gerçekleşen versiyonudur.

---

## Gelişmiş API ve Parametre Manipülasyonu

### HTTP Parameter Pollution (HPP)

Aynı parametre birden fazla kez gönderildiğinde, farklı backend teknolojileri bunu **farklı şekilde** yorumlar:

```
GET /api/order?id=1001&id=2002
```

| Teknoloji | Hangi değeri alır |
|---|---|
| PHP | Son değer (2002) |
| ASP.NET | Tüm değerler birleşik ("1001,2002") |
| Node.js (Express, `qs`) | Dizi olarak her ikisi |

Eğer yetki kontrolü ilk parametre üzerinden yapılıp, asıl sorgu ikinci parametre üzerinden çalışıyorsa (ya da tam tersi), IDOR koruması tamamen atlanabilir. Bu özellikle **farklı ara katmanların (proxy, WAF, uygulama sunucusu) parametreyi farklı yorumladığı** ortamlarda ciddi bir sorundur.

---

### Mass Assignment (Toplu Atama)

Bir güncelleme isteğinde backend, gövdedeki tüm alanları doğrudan nesneye eşliyorsa, saldırgan **görmediği ama var olduğunu tahmin ettiği** alanları ekleyebilir.

**Normal istek:**

```json
PUT /api/v1/profile
{
  "name": "Ahmet",
  "email": "ahmet@mail.com"
}
```

**Saldırganın gönderdiği istek:**

```json
PUT /api/v1/profile
{
  "name": "Ahmet",
  "email": "ahmet@mail.com",
  "is_admin": true,
  "account_id": 5,
  "balance": 999999
}
```

Backend bu alanları filtrelemeden nesneye yazıyorsa, kullanıcı doğrudan **yetki yükseltmesi** yapmış olur. Bu, "field-level IDOR" olarak da anılır — çünkü erişilen şey bir kayıt değil, o kaydın **normalde kullanıcıya kapalı olan bir alanıdır**.

Django REST Framework, Rails (`strong_parameters` olmadan) ve basit Express + Mongoose kombinasyonları bu tür zafiyete tarihsel olarak sık rastlanan örneklerdir.

```python
# ❌ Riskli: gelen tüm alanlar doğrudan modele yazılıyor
user = User.objects.get(id=request.user.id)
for key, value in request.data.items():
    setattr(user, key, value)
user.save()
```

```python
# ✅ Güvenli: sadece izin verilen alanlar güncellenir
ALLOWED_FIELDS = {"name", "email"}
for key, value in request.data.items():
    if key in ALLOWED_FIELDS:
        setattr(user, key, value)
user.save()
```

---

### JSON/XML İçinde Dizi Manipülasyonu

Bazı API'ler tek bir ID yerine bir ID listesi kabul eder (toplu işlem senaryoları). Yetki kontrolü sadece ilk elemanda yapılıp diziye uygulanmazsa, saldırgan diziye başka kullanıcılara ait ID'ler ekleyerek toplu veri sızdırabilir.

```json
POST /api/v1/documents/bulk-download
{
  "ids": [4471, 4472, 9981, 9982]
}
```

Burada `4471` ve `4472` saldırgana ait olsa bile, `9981` ve `9982` başka bir kullanıcıya ait olabilir. Eğer sunucu döngü içinde her ID için ayrı yetki kontrolü yapmıyorsa, tüm belgeler tek istekte sızdırılır.

---

### Content-Type Değişimi ile Filtre Atlatma

Bazı yetki/validasyon middleware'leri yalnızca belirli bir `Content-Type` için çalışacak şekilde yazılır (örneğin sadece `application/json` request body'sini parse edip kontrol eden bir middleware). Saldırgan isteği `application/xml` veya `multipart/form-data` olarak gönderirse, middleware isteği hiç görmeyebilir ama backend'in asıl işleyicisi (farklı bir parser kullanıyorsa) veriyi yine de işleyebilir.

```
Content-Type: application/xml

<request><user_id>1045</user_id></request>
```

Bu teknik doğrudan bir "IDOR türü" değildir ama **erişim kontrolü mekanizmalarını atlatmanın** klasik bir yoludur ve genellikle IDOR ile birlikte zincirlenir.

---

## İş Mantığı (Business Logic) ve Dolaylı IDOR'lar

### İkinci Derece (Second-Order) IDOR

En zor tespit edilen türlerden biridir çünkü zafiyet, veri girildiği anda değil, **başka bir işlem tetiklendiğinde** ortaya çıkar.

**Senaryo:**

1. Kullanıcı, kendi hesabında bir "rapor talebi" oluşturur ve talebe kendi `report_id`'sini verir.
2. Sistem bu talebi bir kuyruğa (queue) alır.
3. Arka plan işçisi (background worker) rapor talebini işlerken, `report_id` değerini **tekrar sorgulamadan**, başka bir bağlamda (örneğin PDF oluşturma servisine) iletir.
4. PDF oluşturma servisi, yetki kontrolünü atlayarak `report_id`'ye karşılık gelen (aslında başka bir kullanıcıya ait) veriyi PDF'e gömer.

Bu senaryoda ilk istek tamamen "normal" görünür; zafiyet, veri **kaydedildikten sonra**, farklı bir bileşende ortaya çıkar. Bu yüzden klasik "tek istek — tek yanıt" testleriyle bulunamaz; **uçtan uca iş akışının** takip edilmesi gerekir.

---

### Çoklu Rol ve Kurumsal Hiyerarşi (B2B SaaS / Multi-Tenancy)

Kurumsal SaaS ürünlerinde veri genellikle bir "tenant" (kiracı/şirket) kimliğine bağlıdır. Yetki kontrolü sadece "bu kullanıcı bu kaydın sahibi mi?" sorusuna odaklanıp "**bu kayıt bu kullanıcının tenant'ına mı ait?**" sorusunu atlarsa, çapraz-tenant IDOR oluşur.

```
GET /api/v1/tenants/77/employees/301
Authorization: Bearer <tenant_88_admin_token>
```

Burada `tenant_88`'in admini, `tenant_77`'nin çalışan kaydına erişebiliyor olabilir — çünkü backend sadece "bu kullanıcı admin mi?" diye bakmış, "hangi tenant'ın admini?" diye bakmamıştır.

Ayrıca aynı şirket içinde bile roller arası (alt kullanıcı → yönetici) sızıntılar mümkündür:

```
GET /api/v1/company/salary-reports/{report_id}
```

Bir "employee" rolündeki kullanıcı, sadece kendi maaş raporuna erişebilmesi gerekirken, `report_id`'yi değiştirerek yöneticinin veya başka bir çalışanın raporuna erişebiliyorsa bu **hem yatay hem dikey** bir IDOR'dur.

---

### Gizli / Alternatif Fonksiyon Uç Noktaları

Aynı kaynağa erişen birden fazla uç nokta olabilir ve geliştiriciler genellikle sadece "ana" uç noktaya yetki kontrolü ekler.

```
/api/v1/users/123            → yetki kontrolü var
/api/v1/export/users/123     → yetki kontrolü unutulmuş
/api/v1/archive/users/123    → yetki kontrolü unutulmuş
/api/v1/internal/users/123   → sadece "internal" olduğu varsayılmış
```

Bu tür uç noktalar genellikle:

* API dokümantasyonunda (Swagger/OpenAPI) sızar
* JavaScript bundle'larında (webpack chunk'ları) referans olarak bulunur
* Eski API versiyonlarında (`/v1/` hâlâ aktifken `/v2/`'ye geçilmiş) unutulur

Bu yüzden IDOR testinde sadece görünen uç noktayı değil, **aynı kaynağa erişen tüm alternatif yolları** haritalamak kritik önem taşır.

---

### Özel Script ile Ölçekli IDOR Testi

Büyük ID aralıklarını manuel test etmek pratik değildir. Rate-limit'lere takılmadan, asenkron ve çok iş parçacıklı bir tarama scripti yazmak IDOR testinde standart bir yaklaşımdır.

```python
import asyncio
import aiohttp

TARGET = "https://target.com/api/v1/invoices/{}"
HEADERS = {"Authorization": "Bearer <dusuk_yetkili_token>"}

async def check_id(session, i, semaphore):
    async with semaphore:
        try:
            async with session.get(TARGET.format(i), headers=HEADERS) as resp:
                if resp.status == 200:
                    print(f"[+] Erişilebilir: {i}")
        except Exception:
            pass

async def main():
    semaphore = asyncio.Semaphore(10)  # eşzamanlı istek sınırı (rate-limit'e takılmamak için)
    async with aiohttp.ClientSession() as session:
        tasks = [check_id(session, i, semaphore) for i in range(1000, 5000)]
        await asyncio.gather(*tasks)

asyncio.run(main())
```

---

## Kaynak Kod Analizi (White-Box Pentest)

Kara kutu (black-box) testte IDOR bulmak zaman alıcıdır; kaynak koda erişim varsa (white-box), zafiyeti çok daha hızlı ve kesin şekilde tespit etmek mümkündür.

### ORM Seviyesinde Eksik Filtreleme

En sık karşılaşılan white-box IDOR nedeni, ORM sorgusuna **tenant/owner filtresinin eklenmesinin unutulmasıdır**.

**Entity Framework (C#) örneği:**

```csharp
// ❌ Riskli: sadece ID'ye göre çekiliyor, sahiplik kontrolü yok
var invoice = db.Invoices.FirstOrDefault(x => x.Id == invoiceId);
return Ok(invoice);
```

```csharp
// ✅ Güvenli: mevcut kullanıcının/tenant'ın sahipliği filtreye dahil
var invoice = db.Invoices
    .FirstOrDefault(x => x.Id == invoiceId && x.TenantId == currentTenant.Id);
if (invoice == null) return Forbid();
return Ok(invoice);
```

**Prisma (Node.js) örneği:**

```javascript
// ❌ Riskli
const doc = await prisma.document.findUnique({ where: { id: docId } });
```

```javascript
// ✅ Güvenli
const doc = await prisma.document.findFirst({
  where: { id: docId, ownerId: req.user.id }
});
if (!doc) return res.status(403).json({ error: "Yetkisiz erişim" });
```

**Hibernate (Java) örneği:**

```java
// ❌ Riskli
Order order = orderRepository.findById(orderId).orElseThrow();
```

```java
// ✅ Güvenli
Order order = orderRepository
    .findByIdAndUserId(orderId, currentUser.getId())
    .orElseThrow(() -> new AccessDeniedException("Yetkisiz"));
```

Kod incelerken aranması gereken kalıp nettir: **`findById` / `findOne` / `.Id ==` gibi tek koşullu sorgular**, eğer hemen ardından ayrı bir yetki kontrolü (if/else, middleware, decorator) yoksa, potansiyel bir IDOR'dur.

---

### Erişim Kontrolü Decorator/Annotation Eksiklikleri

Modern framework'ler yetkilendirmeyi decorator/annotation ile deklaratif hale getirir. Sorun, geliştiricinin bunu **bazı fonksiyonlarda unutmasıdır**.

**NestJS örneği:**

```typescript
// ❌ Riskli: guard eksik, herhangi bir authenticated kullanıcı erişebilir
@Get(':id')
getInvoice(@Param('id') id: string) {
  return this.invoiceService.findById(id);
}
```

```typescript
// ✅ Güvenli: hem authentication hem ownership guard'ı var
@UseGuards(JwtAuthGuard, InvoiceOwnershipGuard)
@Get(':id')
getInvoice(@Param('id') id: string, @CurrentUser() user: User) {
  return this.invoiceService.findByIdForUser(id, user.id);
}
```

**Spring (Java) örneği:**

```java
// ❌ Riskli: @PreAuthorize eksik
@GetMapping("/orders/{id}")
public Order getOrder(@PathVariable Long id) {
    return orderService.findById(id);
}
```

```java
// ✅ Güvenli: sahiplik SpEL ifadesiyle kontrol ediliyor
@PreAuthorize("@orderSecurity.isOwner(#id, authentication)")
@GetMapping("/orders/{id}")
public Order getOrder(@PathVariable Long id) {
    return orderService.findById(id);
}
```

**ASP.NET Core örneği:**

```csharp
// ❌ Riskli: [Authorize] var ama resource-level kontrol yok
[Authorize]
[HttpGet("{id}")]
public IActionResult GetDocument(int id) { ... }
```

```csharp
// ✅ Güvenli: resource-based authorization handler kullanılıyor
[Authorize]
[HttpGet("{id}")]
public async Task<IActionResult> GetDocument(int id)
{
    var doc = await _repo.GetById(id);
    var result = await _authService.AuthorizeAsync(User, doc, "OwnerPolicy");
    if (!result.Succeeded) return Forbid();
    return Ok(doc);
}
```

White-box incelemede en verimli yöntem, **tüm route/controller dosyalarını tarayıp**, yetki decorator'ı bulunmayan veya "resource-level" kontrol içermeyen (sadece `[Authorize]` gibi genel authentication kontrolü olan) fonksiyonları listelemektir. Statik analiz araçları (Semgrep gibi) bu kalıbı özel kurallarla otomatik taramak için kullanılabilir:

```yaml
# Basit bir Semgrep kural mantığı örneği
rules:
  - id: missing-ownership-check
    pattern: |
      @Get(...)
      $FUNC(...) {
        return $SERVICE.findById($ID);
      }
    message: "Resource-level yetki kontrolü eksik olabilir"
    severity: WARNING
```

---

## IDOR Nasıl Tespit Edilir? (Metodoloji Özeti)

1. **Kaynak haritalama:** Uygulamadaki tüm ID/referans taşıyan uç noktaları çıkar (URL, body, header, cookie).
2. **Çoklu hesap kur:** En az iki farklı kullanıcı (aynı yetki seviyesinde) ve mümkünse farklı rol/tenant'lardan hesaplar oluştur.
3. **Çapraz test:** Kullanıcı A'nın oturumuyla, Kullanıcı B'ye ait ID'lere erişmeyi dene (yatay).
4. **Rol testi:** Düşük yetkili kullanıcının oturumuyla, yüksek yetkili kaynaklara erişmeyi dene (dikey).
5. **Fonksiyon çeşitlemesi:** Sadece GET değil, PUT/PATCH/DELETE ve toplu (bulk) uç noktaları da test et.
6. **İkincil kanalları izle:** PDF export, e-posta bildirimi, webhook, arka plan işi gibi dolaylı veri akışlarını takip et.
7. **Farklı formatları dene:** JSON yerine XML/form-data, HPP (`?id=1&id=2`) gibi parser farklılıklarını test et.

---

## Ne Yapılmalı / Ne İşe Yaramaz

### ✅ İşe Yarar

* Her istekte **resource-level** yetki kontrolü (sadece authentication değil, ownership/tenant kontrolü)
* Tahmin edilemez ID'ler (UUIDv4) + **buna rağmen** yetki kontrolü (obscurity tek başına yeterli değildir)
* Merkezi yetkilendirme katmanı (her controller'da tekrar tekrar yazmak yerine ortak middleware/guard)
* Deny-by-default yaklaşımı: açıkça izin verilmemiş her erişim reddedilir
* Otomatik testler (integration test) ile "kullanıcı B, kullanıcı A'nın kaydına erişemez" senaryolarının CI/CD'ye eklenmesi

---

### 🚑 Virtual Patch

Gerçek dünyada çoğu zaman "doğru" çözüm (merkezi yetkilendirme katmanı, DTO'lar, resource-based authorization) hazır ama **hemen o gün devreye alınacak bir yama** gerekir. Aşağıdaki 5 yöntem, mevcut kod tabanına dokunmadan, sadece ilgili endpoint(ler)e eklenerek **saatler içinde** riski büyük ölçüde azaltır. Bunlar kalıcı çözüm değildir — asıl amaç kanamayı durdurup, doğru fix'e zaman kazandırmaktır.

**1. İşlem Bazlı Nonce/Random Token (Tek Kullanımlık Referans)**

Kaynağa doğrudan `id` ile değil, sadece o istemciye/oturuma özel, kısa ömürlü ve tek kullanımlık bir `nonce` ile erişilmesini zorunlu kılın. Saldırgan `id`'yi tahmin etse bile, geçerli bir `nonce` olmadan istek reddedilir.

```python
# İlgili kaynağı görüntülerken bir nonce üretilip cache'e (Redis) yazılır
nonce = secrets.token_urlsafe(16)
redis.setex(f"nonce:{nonce}", 300, f"{request.user.id}:{invoice_id}")

# Sonraki istekte nonce doğrulanır, eşleşmezse veya süresi geçmişse reddedilir
owner = redis.get(f"nonce:{req.args['nonce']}")
if not owner or owner != f"{request.user.id}:{invoice_id}":
    return abort(403)
```

**2. ID'yi HMAC ile İmzalama (Signed Reference)**

Kaynağa erişim linki/parametresi, sunucu tarafı gizli anahtarla imzalanır. Saldırgan ID'yi tahmin etse bile, geçerli bir imza üretemediği için erişemez. Uygulama mantığına dokunmadan, sadece link üretim ve doğrulama noktasına eklenir.

```python
import hmac, hashlib

def sign_id(resource_id, user_id):
    msg = f"{resource_id}:{user_id}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()[:16]

# Doğrulama: gelen sig, beklenen sig ile eşleşmiyorsa reddet
expected = sign_id(invoice_id, request.user.id)
if not hmac.compare_digest(request.args.get("sig", ""), expected):
    return abort(403)
```

**3. Geçici Middleware/Interceptor ile "Hızlı Yama" (Quick-Patch Guard)**

Kod tabanının tamamını değiştirmeden, sadece etkilenen route grubunun önüne **tek bir kontrol noktası** eklenir. Bu, kalıcı çözüme geçilene kadar tüm ilgili endpoint'leri tek satırda korur.

```javascript
// Tüm /api/v1/invoices/:id rotalarının önüne eklenen geçici guard
app.use('/api/v1/invoices/:id', async (req, res, next) => {
  const invoice = await Invoice.findById(req.params.id);
  if (!invoice || invoice.ownerId !== req.user.id) return res.status(403).end();
  next();
});
```

**4. Response'u Owner Kontrolüyle Filtreleme (Fail-Safe Post-Check)**

Sorgu tarafını değiştirmeye vakit yoksa, en azından **veri döndürülmeden hemen önce** son bir sahiplik kontrolü eklenir. Sorgu yanlış tasarlanmış olsa bile, yanlış kullanıcıya veri gitmesini bu son adım engeller.

```python
invoice = get_invoice_by_id(invoice_id)  # mevcut, değiştirilmeyen sorgu
if invoice.owner_id != current_user.id:
    log.warning(f"IDOR denemesi: user={current_user.id} target={invoice_id}")
    return abort(403)
return jsonify(invoice)
```

**5. Şüpheli ID Taramasını Log + Alarm ile Yakalama (Geçici Tespit Katmanı)**

Fix devreye girene kadar, aynı kullanıcının kısa sürede çok sayıda farklı ID denediği durumlar (klasik IDOR tarama davranışı) tespit edilip otomatik olarak engellenir/alarm üretir. Bu bir "önleme" değil ama **istismarı gerçek zamanlı durdurur**.

```python
key = f"id_attempts:{current_user.id}"
attempts = redis.incr(key)
redis.expire(key, 60)
if attempts > 20:  # 60 saniyede 20'den fazla farklı ID denemesi şüpheli
    alert_security_team(current_user.id)
    return abort(429)
```

**Dikkat edilmesi gerekenler:**

* Bu 5 yöntem **geçicidir** — asıl çözüm hâlâ resource-level yetki kontrolünün merkezi katmanda kalıcı olarak eklenmesidir.
* Nonce/imza tabanlı çözümler **yeni bir bypass yüzeyi** açmamalı: secret key'in güvenli saklanması, nonce'ların gerçekten tek kullanımlık ve kısa ömürlü olması şarttır.
* Log + alarm katmanı tek başına savunma değildir; sadece **zaman kazandırır**, saldırgan yavaşlatılmış bir tarama ile hâlâ başarılı olabilir.
* Yama sonrası mutlaka **etkilenen tüm endpoint'ler** (export, archive, internal, bulk gibi alternatif yollar dahil) taranıp aynı kontrolün eklendiğinden emin olunmalı.
* Geçici çözüm production'a alındıktan sonra, kalıcı fix (merkezi middleware/guard + DTO + owner filtresi ORM seviyesinde) backlog'a değil, **aynı sprint'e** yazılmalıdır — aksi halde "geçici" çözüm kalıcılaşır.

---

### ❌ Ne İşe Yaramaz

* Sadece ID'yi UUID yapmak (yetki kontrolü hâlâ yoksa fark etmez)
* Sadece frontend'de "buton gizlemek" (backend hâlâ isteği işliyorsa saldırgan doğrudan API'ye gider)
* Sadece belirli uç noktalara yetki eklemek, alternatif/export/archive uç noktalarını unutmak
* Rate-limit'e güvenmek (yavaş da olsa saldırgan yine de tüm ID uzayını tarayabilir)

**Gerçek çözüm, her kaynağa erişimin "bu istek sahibi bu kaynağın sahibi/yetkilisi mi?" sorusunu backend'de, merkezi ve tutarlı şekilde sormasıdır. Yukarıdaki hızlı çözümler bu soruya kalıcı cevap verilene kadar riski azaltmak içindir.**

---

## Yaygın Senaryolar

* Yatay yetki atlatma (aynı seviyede başka kullanıcı verisi)
  `GET /api/v1/orders/1044` → `GET /api/v1/orders/1045`

* Dikey yetki yükseltme (mass assignment ile)
  `PUT /api/v1/profile { "is_admin": true }`

* Çoklu tenant sızıntısı
  `GET /api/v1/tenants/77/employees/301` (farklı tenant admin token'ıyla)

* Toplu veri sızdırma (JSON dizi manipülasyonu)
  `POST /api/v1/documents/bulk-download { "ids": [4471, 9981, 9982] }`

---
