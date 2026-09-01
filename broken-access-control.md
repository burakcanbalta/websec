<img width="1024" height="585" alt="broken-access-control-1024x585" src="https://github.com/user-attachments/assets/eb7d0e6d-86b9-457c-98fc-a4cbab9fbda8" />

**Broken Access Control (Kırık Erişim Kontrolü)**, bir uygulamanın kimliği doğrulanmış ya da doğrulanmamış bir kullanıcının **neyi yapmaya yetkili olduğunu** düzgün şekilde denetlememesi sonucu ortaya çıkan yetkilendirme (authorization) hatasıdır. [OWASP Top 10:2025](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) listesinde **A01** olarak birinci sırada yer alır — ve bu sıralama tesadüf değildir: OWASP'ın test verilerine göre incelenen uygulamaların **%100'ünde** bir tür erişim kontrolü zafiyeti tespit edilmiştir. 2025 revizyonunda kategoriye yapılan en önemli ekleme ise **SSRF (Server-Side Request Forgery)**'nin buraya dahil edilmesidir — çünkü sahte bir sunucu-taraflı istek de özünde aynı hatadan doğar: "bu isteğin şu kaynağa gitmesine izin var mı?" sorusu bir yerde sorulmamıştır.

---

## 1. Temel Kavramlar: Authentication ≠ Authorization

Yeni başlayanların en sık karıştırdığı nokta budur:

* **Authentication (Kimlik Doğrulama):** "Sen kimsin?" — şifre, biyometrik, token ile kanıtlanır.
* **Authorization (Yetkilendirme):** "Sen bunu yapmaya yetkili misin?" — kimliği doğrulanmış bir kullanıcının hangi kaynaklara, hangi işlemlere erişebileceğini belirler.

Broken Access Control, **authentication'ın doğru çalıştığı ama authorization'ın hiç sorulmadığı veya yanlış yerde sorulduğu** durumlarda ortaya çıkar. Bu yüzden SAST/DAST araçları bu zafiyetleri çoğu zaman kaçırır: kod sözdizimsel olarak "doğru" çalışır, sadece kimin bu işlemi yapmaya yetkili olduğu sorusu hiç sorulmamıştır.

### Erişim Kontrolü Türleri

| Tür | Tanım | Örnek |
|---|---|---|
| **Yatay (Horizontal)** | Aynı yetki seviyesindeki başka bir kullanıcının verisine erişim | `user_id=1044` → `user_id=1045` |
| **Dikey (Vertical)** | Daha düşük yetkiden daha yüksek yetkiye sızma | Normal kullanıcı → admin fonksiyonu |
| **Bağlamsal (Context-Dependent)** | Doğru sırayla, doğru durumda yapılmayan işlemler | Ödeme adımı atlanıp sipariş tamamlanmış gibi işaretlenmesi |

---

## 2. Klasik Erişim Kontrolü Açıkları (Temel Seviye)

İleri seviyeye geçmeden önce, hâlâ en sık karşılaşılan temel kalıpları hızlıca hatırlamakta fayda var:

**Force Browsing / Parametre Kurcalama:** Kullanıcıya gösterilmeyen ama var olan bir URL'ye doğrudan gidilmesi.

```
GET /admin/dashboard
```

Frontend bu linki göstermese bile, backend isteği kontrolsüz işliyorsa erişim sağlanır.

**IDOR (Insecure Direct Object Reference):** Kaynak ID'sinin sahiplik kontrolü yapılmadan servis edilmesi — bu konuyu ayrı ve kapsamlı şekilde IDOR yazımızda derinlemesine işledik, burada tekrar etmiyoruz.

**CORS Yanlış Yapılandırması:**

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Bu kombinasyon spesifikasyona aykırıdır ve tarayıcılar tarafından reddedilmesi gerekir, ancak eski tarayıcı davranışları veya hatalı proxy/gateway katmanları yüzünden credential taşıyan cross-origin isteklerin sızmasına yol açabilecek yapılandırma hataları hâlâ karşımıza çıkar.

**Sadece Frontend'de Gizleme:** Bir "Sil" butonunun sadece CSS ile gizlenmesi, backend endpoint'i hâlâ isteği işliyorsa hiçbir şey ifade etmez.

Şimdi bu temelin üzerine, günümüz mikro servis / API-first mimarilerinde karşımıza çıkan **ileri seviye** teknikleri inceleyelim.

---

## 3. HTTP / Yönlendirme Katmanı Çatışmaları (Proxy vs. Back-End Uyuşmazlıkları)

Modern mimarilerde istek, kullanıcıdan çıkıp gerçek uygulamaya ulaşana kadar birden fazla katmandan geçer: CDN → WAF → API Gateway/Reverse Proxy → Load Balancer → Uygulama sunucusu. **Her katman aynı isteği tam olarak aynı şekilde yorumlamak zorunda değildir** — ve bu uyuşmazlık, tam olarak burada bir erişim kontrolü boşluğu açar.

### 3.1 Path Normalization (Yol Normalizasyonu) Açıkları

Nginx, Envoy gibi ters proxy'ler ile arkadaki uygulama sunucusu, URL yolundaki özel karakterleri **farklı şekilde** normalize edebilir.

```
GET /api/v1/admin/..;/user
GET /api/v1/user/../admin/panel
```

Proxy, `/api/v1/admin/..;/user` yolunu "aslında `/api/v1/user`'a gidiyor, admin'e dokunmuyor" diye değerlendirip WAF kuralını tetiklemeyebilir — ama arkadaki Java/Spring tabanlı sunucu `;` karakterini bir matrix parametresi olarak yorumlayıp isteği fiilen `/api/v1/admin/user`'a yönlendirebilir. Sonuç: **proxy'nin gördüğü path ile sunucunun işlediği path birbirinden farklıdır**, ve yetkilendirme kararı proxy seviyesinde verilmiş olabilir.

### 3.2 HTTP Method Overriding

Bazı framework'ler, HTTP metodunu doğrudan istek satırından değil, bir header veya body parametresinden de okuyabilir — bu, eski tarayıcı/proxy uyumluluğu için eklenmiş bir "kolaylık" özelliğidir, ama güvenlik açısından bir arka kapıdır.

```http
POST /api/v1/users/44 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

```
POST /api/v1/resource
_method=PUT
```

WAF veya API Gateway sadece görünen `POST` metoduna göre kural işletiyorsa (örneğin "DELETE yasak, POST serbest" gibi), saldırgan asıl niyetini bu gizli override alanına saklayarak filtreyi atlatır.

### 3.3 Hop-by-Hop Header Enjeksiyonu

HTTP/1.1 spesifikasyonundaki `Connection` header'ı, hangi header'ların "sadece bir sonraki hop için geçerli olduğunu" belirtebilir. Bazı proxy implementasyonları bu header'ı kör bir şekilde uygular:

```http
GET /api/v1/profile HTTP/1.1
Connection: close, X-User-Id
X-User-Id: 44
```

Eğer proxy, `Connection` header'ında listelenen alanları **kendi ekleyeceği kimlik doğrulama header'ından sonra** siliyorsa, ve arkadaki servis `X-User-Id`'nin varlığına güvenip "gateway tarafından doğrulanmış" varsayıyorsa, saldırgan bu mekanizmayı kullanarak gateway'in eklediği gerçek kimlik header'ını silip **kendi sahte header'ını** enjekte edebilir.

### 3.4 URI Parsing Tutarsızlıkları

Aynı URL, farklı dillerde yazılmış bileşenler tarafından **farklı şekilde parçalanabilir (split)**:

```
/api/v1/user%00/admin
/api/v1/user%0a/admin
/api/v1/user?/../admin
/api/v1/user#/../admin
```

* Null byte (`%00`) bazı eski C tabanlı parser'larda string'i erken sonlandırabilir.
* `%0a` (newline) bazı log/header parser'larını veya regex tabanlı filtreleri şaşırtabilir.
* `?`, `#`, `;` karakterleri Java (Spring), Python (Django/Flask) ve Go standart kütüphanelerinde **farklı noktalarda** path'i keser.

Bu farklılık, WAF'ın "path traversal yok" diye onayladığı bir isteğin, arkadaki sunucu tarafından tamamen farklı (ve yetkisiz) bir kaynağa yönlendirilmesine yol açabilir.

---

## 4. Mikro Servis ve Güven İlişkisi İstismarı

Monolitik uygulamalarda tek bir yetkilendirme katmanı yeterliyken, mikro servis mimarilerinde **her serviste ayrı ayrı** doğrulama yapılması gerekir. Geliştiriciler genellikle "zaten gateway kontrol etti" varsayımıyla iç servisler arasındaki kontrolleri gevşetir — bu varsayım, saldırganın tam olarak hedeflediği güven boşluğudur.

### 4.1 SSRF ile Internal Trust Sömürüsü

Dışarıya kapalı, sadece iç ağdan erişilebilir olması beklenen uç noktalar (`/internal/v1/privileges`, `/internal/admin/config`) genellikle **hiçbir kimlik doğrulama içermez** — çünkü "zaten dışarıdan erişilemiyor" varsayılır. Uygulamanın kendi içinde bir SSRF açığı (webhook, PDF/rapor oluşturucu, resim indirme servisi) varsa, saldırgan bu güven varsayımını doğrudan istismar eder:

```json
POST /api/v1/reports/generate
{
  "source_url": "http://internal-service.local/internal/v1/privileges?user_id=1"
}
```

Uygulama bu URL'ye kendi adına istek attığında, **hiçbir token taşımadan**, sadece "iç ağdan geldiği" için privilige verisini döner — saldırgan bu veriyi rapor çıktısı veya hata mesajı üzerinden dolaylı olarak sızdırır.

### 4.2 ID Token vs. Access Token Karışıklığı

OAuth2/OIDC mimarilerinde iki farklı token türü vardır ve bunların amacı kesinlikle farklıdır:

* **ID Token:** Sadece kullanıcının kimliğini (kim olduğunu) taşır, kimlik sağlayıcı tarafından imzalanır.
* **Access Token:** Belirli bir kaynağa erişim yetkisini taşır.

Bazı zayıf API Gateway yapılandırmaları, gelen JWT'nin **hangi tür token olduğunu** (`typ` claim'i veya `aud` alanı üzerinden) kontrol etmeden, sadece imzasının geçerli olup olmadığına bakar:

```json
{
  "iss": "https://idp.target.com",
  "sub": "1044",
  "aud": "id-token-audience",
  "typ": "ID"
}
```

Eğer gateway bu ID token'ı bir access token gibi kabul edip kaynak servise iletirse, saldırgan **hiçbir zaman gerçek bir yetkilendirme akışından geçmeden**, sadece kimlik doğrulama akışının bir yan ürünüyle kaynaklara erişebilir.

### 4.3 Kayıp Hizmet-İçi Yetkilendirme (Service-to-Service)

API Gateway, dış dünyadan gelen isteği başarıyla doğrulayıp kullanıcı rolünü bir header'a (`X-User-Role: user`) yazarak iç servise iletebilir. Ama A servisi, B servisiyle konuşurken bu rolü **tekrar sorgulamadan**, "zaten iç ağdan geliyor, güvenilir" varsayımıyla işlem yapıyorsa:

```
[Gateway] → X-User-Role: user → [Servis A] → (rol kontrolü yok) → [Servis B: admin fonksiyonu]
```

Servis A içinde bulunan **herhangi bir zafiyet** (SSRF, template injection, deserialize açığı), saldırgana Servis A'nın kimliğiyle Servis B'ye "içeriden, güvenilir" bir istek attırma imkânı tanır — ve Servis B, bu isteğin arkasındaki gerçek kullanıcının rolünü hiç sorgulamaz.

---

## 5. İleri Seviye Token ve Kriptografik Sabotaj

### 5.1 JWT JWKS Sızdırma ve Sahtecilik

JWT header'ındaki `jku` (JWK Set URL) alanı, imzayı doğrulamak için kullanılacak public key setinin **nereden** çekileceğini belirtir:

```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/.well-known/jwks.json",
  "kid": "attacker-key-1"
}
```

Sunucu bu URL'yi doğrulamadan (whitelist yapmadan) kullanıyorsa, saldırgan kendi sunucusunda bir JWKS dosyası barındırıp **kendi ürettiği anahtar çiftiyle imzaladığı** bir token'ı sisteme "geçerli" olarak kabul ettirebilir. Aynı sömürü, uygulamanın kendi üzerinde açık bir SSRF noktası varsa, `jku` değerini bu SSRF'i tetikleyecek bir iç adrese yönlendirerek de gerçekleştirilebilir.

```python
# Saldırganın barındırdığı sahte JWKS
{
  "keys": [{
    "kty": "RSA", "kid": "attacker-key-1",
    "n": "...", "e": "AQAB"
  }]
}
```

### 5.2 Oturum Bulmacası (Session Puzzling)

Bazı uygulamalar, session nesnesindeki geçici alanları **birden fazla farklı akış için yeniden kullanır** — bu, geliştirme kolaylığı sağlar ama tehlikeli bir yan etki taşır.

**Senaryo:**

1. Kullanıcı şifre sıfırlama akışını başlatır → sunucu `session["user_id"] = target_id` ve `session["reset_stage"] = "pending"` yazar.
2. Kullanıcı bu akışı **tamamlamadan** doğrudan profil sayfasına gider.
3. Profil sayfası, `session["user_id"]`'nin "giriş yapmış kullanıcı" anlamına geldiğini varsayar — ama bu alan aslında şifre sıfırlama akışı tarafından, **kimlik doğrulaması yapılmadan** yazılmıştır.

```python
# ❌ Riskli: aynı session anahtarı iki farklı akış tarafından paylaşılıyor
def start_password_reset(target_user_id):
    session["user_id"] = target_user_id  # henüz doğrulanmamış!
    session["reset_stage"] = "pending"

def get_profile():
    # user_id'nin "giriş yapılmış" anlamına geldiği yanlış varsayılıyor
    return db.get_user(session["user_id"])
```

Saldırgan, kurbanın e-posta adresiyle şifre sıfırlama akışını tetikleyip **hiç tamamlamadan** doğrudan `/profile` isteği atarak kurbanın verisine erişebilir.

### 5.3 Kriptografik Rastgelelik Eksikliği

Özel (custom) olarak yazılmış token üretim algoritmaları, zaman damgası veya zayıf bir PRNG'den (`Math.random()`, tohumlanmamış `rand()`) türetiliyorsa:

```javascript
// ❌ Riskli: token, tahmin edilebilir zaman damgasından türetiliyor
const token = crypto.createHash('md5')
  .update(`${Date.now()}-${userId}`)
  .digest('hex');
```

Saldırgan, üretilen birkaç token'ın zaman damgasını (response header'larındaki `Date` alanı veya yaklaşık istek zamanı üzerinden) gözlemleyip, aynı milisaniye aralığını brute-force ederek **bir sonraki admin token'ını** önceden hesaplayabilir.

---

## 6. İş Mantığı ve Durum Makinesi (State Machine) Kırılmaları

### 6.1 Negatif ve Taşma (Overflow) Sınır Testleri

Yetki kontrolü yapan fonksiyonlar, beklenmedik girdi türleriyle karşılaştığında genellikle **exception fırlatır** — ve bu exception'ın nasıl işlendiği kritik önem taşır.

```python
# ❌ Riskli: hata durumunda varsayılan olarak erişim veriliyor
def check_permission(user_id, resource_id):
    try:
        resource = db.get(resource_id)
        return resource.owner_id == user_id
    except Exception:
        return True  # "hata oldu, muhtemelen sorun yok" gibi tehlikeli bir varsayım
```

```
GET /api/v1/orders/-1
GET /api/v1/orders/2147483648
GET /api/v1/orders/999999999999999999999999999
```

`-1` gibi negatif bir ID, `2147483648` gibi 32-bit integer taşması yaratan bir değer veya aşırı uzun bir string, `resource_id` alanını bekleyen sorguyu bir exception'a düşürebilir. Yukarıdaki gibi kötü tasarlanmış bir `try/except` bloğu, bu exception'ı "erişim izni ver" olarak yorumluyorsa, saldırgan **sadece anlamsız bir ID göndererek** yetki kontrolünü tamamen atlatmış olur.

### 6.2 Zaman Tabanlı Yarış Durumu (Deep Race Conditions)

HTTP/2'nin çoklama (multiplexing) özelliği, tek bir TCP bağlantısı üzerinden **onlarca isteğin aynı anda** gönderilmesine izin verir. Yetki kontrolü ile işlemin gerçekleştirilmesi arasında (check-then-act) bir zaman penceresi varsa, bu pencereyi eşzamanlı isteklerle "yarışarak" istismar etmek mümkündür.

```python
import httpx, asyncio

async def race_role_update(client):
    return await client.post(
        "https://target.com/api/v1/account/update-role",
        json={"role": "admin"}
    )

async def race_attack():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [race_role_update(client) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        print(f"Başarılı istek sayısı: {sum(1 for r in results if r.status_code == 200)}")

asyncio.run(race_attack())
```

Veri tabanı seviyesindeki satır kilitleme (row locking) mekanizması, isteklerin sırayla işleneceği varsayımıyla yazılmışsa, aynı milisaniyede gelen 50 istek, **kilitlenme henüz devreye girmeden** birden fazla kez "rol güncelleme" veya "bakiye çekme" işlemini başarıyla tamamlayabilir.

### 6.3 Mantıksal Durum Atlama (State Machine Bypass)

Çok adımlı bir iş akışında (`/checkout` → `/payment` → `/success`), her adımın bir öncekini **gerçekten tamamladığını doğrulamak** backend'in sorumluluğundadır — sadece sıralı çağrılmasını "yeterli" saymak tehlikelidir.

```
POST /api/v1/checkout        → sepet oluşturulur, checkout_id döner
POST /api/v1/payment/cancel  → ödeme adımı iptal edilir
POST /api/v1/success         → { "checkout_id": "abc123" }
```

Eğer `/success` uç noktası, sadece `checkout_id`'nin var olup olmadığına bakıp, **gerçekten bir ödeme kaydının başarıyla tamamlandığını** doğrulamıyorsa, saldırgan ödeme adımını hiç geçmeden veya iptal ettikten hemen sonra doğrudan `/success`'e istek atarak siparişi "ödendi" durumuna geçirebilir.

```python
# ❌ Riskli: sadece checkout_id'nin varlığına bakılıyor
def mark_success(checkout_id):
    checkout = db.get_checkout(checkout_id)
    if checkout:  # ödeme durumu hiç kontrol edilmiyor
        checkout.status = "paid"
        checkout.save()
```

---

## 7. Gelişmiş API ve Veri Katmanı (Database/ORM) Sızıntıları

### 7.1 GraphQL Query Overloading & Batching

Klasik yetkilendirme middleware'leri genellikle **HTTP isteği başına** çalışacak şekilde tasarlanır. GraphQL'in alias mekanizması, tek bir HTTP isteğinde **yüzlerce sorgu/mutation**'ı birleştirmeye izin verir:

```graphql
mutation {
  m1: updateRole(userId: 1044, role: "admin") { success }
  m2: updateRole(userId: 1045, role: "admin") { success }
  m3: deleteUser(userId: 2001) { success }
  # ... yüzlerce alias
}
```

Rate limiter ve bazı basit yetkilendirme filtreleri "istek sayısına" göre çalışıyorsa, bu tek istek hem rate limit'i hem de "istek başına bir kez çalışan" kontrol mantığını görünürde hiç tetiklemez.

### 7.2 Mass Assignment + ORM İlişki Enjeksiyonu

Klasik mass assignment sadece düz alanları (`is_admin: true`) hedeflerken, ORM ilişkileri üzerinden yapılan enjeksiyon çok daha derin bir etki yaratabilir:

```json
PUT /api/v1/profile
{
  "user_id": 5,
  "organization": { "id": 1 }
}
```

Backend, gelen `organization` nesnesini doğrudan ORM'e (`user.organization = Organization.objects.get(id=data['organization']['id'])`) map ediyorsa, saldırgan **tek bir istekte** hangi şirkete bağlı olduğunu değiştirip, o şirkete tanımlı tüm alt yetkileri (roller, veri erişimi, fatura bilgileri) devralabilir.

```python
# ❌ Riskli: ilişkisel alanlar filtrelenmeden ORM'e yazılıyor
for key, value in request.data.items():
    if key == "organization":
        user.organization = Organization.objects.get(id=value["id"])
    else:
        setattr(user, key, value)
user.save()
```

### 7.3 BSON/NoSQL Tip Değişimi

API, `user_id` alanının **string** olmasını beklerken, saldırgan bir MongoDB operatör nesnesi gönderirse:

```json
POST /api/v1/orders/search
{ "user_id": { "$ne": 1 } }
```

Eğer yetki kontrolü basitçe `user_id == session.user_id` şeklinde doğrusal (ve tip kontrolsüz) yapılıyorsa, backend bu JSON'u doğrudan bir Mongoose/PyMongo sorgusuna aktarabilir:

```javascript
// ❌ Riskli: gelen filtre doğrudan sorguya taşınıyor
const orders = await Order.find({ user_id: req.body.user_id });
```

`{"$ne": 1}` operatörü "user_id'si 1 olmayan her şey" anlamına geldiği için, sorgu fiilen **oturum sahibi dışındaki herkesin** siparişlerini döner — klasik string karşılaştırması burada tamamen anlamsızlaşır çünkü backend hiçbir zaman "bu bir operatör nesnesi mi, düz bir ID mi?" sorusunu sormamıştır.

```python
# ✅ Güvenli: tip kesin olarak zorlanıyor, operatör nesneleri reddediliyor
if not isinstance(request.json.get("user_id"), (str, int)):
    return abort(400)
```

---

## 8. Tespit Metodolojisi

1. **Katman haritalama:** İsteğin geçtiği tüm katmanları (CDN, WAF, gateway, servis, ORM) çıkar ve her katmanın aynı isteği nasıl yorumladığını karşılaştır.
2. **Farklı encoding/parser testleri:** Aynı path'i `%00`, `%0a`, `;`, `..;` gibi varyasyonlarla farklı katmanlara göndererek tutarsızlık ara.
3. **Token türü karışıklığı testi:** ID token'ı access token gerektiren uç noktalara göndermeyi dene.
4. **Sınır değer testleri:** Negatif, taşma yaratan ve aşırı uzun ID/miktar değerleriyle hata işleme davranışını gözlemle.
5. **Eşzamanlı istek testi:** Kritik durum değişikliği yapan uç noktalara (rol güncelleme, bakiye işlemi) HTTP/2 üzerinden paralel istek gönderip race condition ara.
6. **State machine atlama testi:** Çok adımlı akışlarda ara adımları atlayıp/iptal edip doğrudan son adıma istek at.
7. **GraphQL/NoSQL girdi manipülasyonu:** Alias batching ve operatör nesneleri (`$ne`, `$gt`) ile filtre/limit mantığını test et.

---

## Virtual Patch — Acil Durum Yaması

Gerçek dünyada sitede/üründe **bugün** bu tür bir açık tespit edilirse, kalıcı çözüm (merkezi yetkilendirme katmanı, DTO'lar, mimari değişiklik) hazır olana kadar **saatler içinde** devreye alınabilecek geçici yamalar aşağıdadır. Bunlar kalıcı çözüm değildir — amaç kanamayı durdurup doğru fix'e zaman kazandırmaktır.

**1. Gateway Seviyesinde Path Normalizasyon Zorunluluğu**

Proxy ve backend'in path'i farklı yorumlaması riskini anında azaltmak için, gateway seviyesinde tüm gelen path'ler tek bir normalizasyon fonksiyonundan geçirilip **decode edilmiş, temizlenmiş** haliyle backend'e iletilir.

```nginx
# NGINX: şüpheli path karakterlerini anında reddet
location /api/ {
    if ($request_uri ~* "(\.\.|;|%00|%0a)") {
        return 400;
    }
    proxy_pass http://backend;
}
```

**2. HTTP Method Override Header'larını Anında Devre Dışı Bırakma**

```javascript
// Express: override header/parametrelerini gateway seviyesinde tamamen yok say
app.use((req, res, next) => {
  delete req.headers['x-http-method-override'];
  if (req.body) delete req.body._method;
  next();
});
```

**3. ID/Access Token Ayrımını Acilen Zorlama**

```python
# ✅ Acil patch: gelen token'ın türü explicit olarak kontrol ediliyor
claims = decode_jwt(token)
if claims.get("typ") != "access" or claims.get("aud") != EXPECTED_AUDIENCE:
    return abort(401)
```

**4. Hata Durumunda Fail-Closed Zorunluluğu**

En kritik ve en hızlı uygulanabilecek yama budur — tüm yetki kontrol fonksiyonlarındaki "hata olursa izin ver" mantığı tersine çevrilir.

```python
# ✅ Acil patch: her exception erişimi reddeder, asla varsayılan olarak izin vermez
def check_permission(user_id, resource_id):
    try:
        resource = db.get(resource_id)
        return resource.owner_id == user_id
    except Exception:
        log.warning(f"Yetki kontrolü hata verdi: user={user_id} resource={resource_id}")
        return False  # fail-closed
```

**5. Kritik State-Changing Endpoint'lere Acil Idempotency Kilidi**

Race condition'a açık uç noktalara (rol güncelleme, bakiye işlemi, sipariş tamamlama), mimariyi değiştirmeden **tek satırlık bir distributed lock** eklenir.

```python
# ✅ Acil patch: aynı kaynak için eşzamanlı işlemi Redis kilidiyle engelle
lock_key = f"lock:role_update:{user_id}"
if not redis.set(lock_key, "1", nx=True, ex=5):
    return abort(429)  # zaten işlemde, tekrar dene
try:
    update_role(user_id, new_role)
finally:
    redis.delete(lock_key)
```

**6. State Machine Adımlarını Acilen Sunucu Tarafında Zincirleme**

```python
# ✅ Acil patch: her adım bir öncekinin gerçekten tamamlandığını doğrular
def mark_success(checkout_id):
    checkout = db.get_checkout(checkout_id)
    if not checkout or checkout.payment_status != "confirmed":
        return abort(403)  # ödeme gerçekten onaylanmamışsa reddet
    checkout.status = "paid"
    checkout.save()
```

**7. GraphQL'e Acil Alias/Derinlik Sınırı**

```javascript
const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5), createComplexityLimitRule(1000)] // acil sınır
});
```

**8. NoSQL Operatör Enjeksiyonuna Karşı Acil Tip Zorlama**

```python
# ✅ Acil patch: beklenmeyen tipte (dict/operator) girdi anında reddedilir
for field in ("user_id", "resource_id"):
    if isinstance(request.json.get(field), dict):
        return abort(400)
```

**Dikkat edilmesi gerekenler:**

* Bu yamalar **geçicidir** — asıl çözüm, tüm katmanlar arasında tutarlı, merkezi ve deny-by-default bir yetkilendirme mimarisidir.
* Gateway seviyesinde eklenen bir kural, backend'e **doğrudan erişilebilen** başka bir yol (internal network, eski API versiyonu, farklı bir gateway) varsa etkisiz kalır — bu yollar mutlaka envanterden kontrol edilmelidir.
* Fail-closed'a geçiş, gerçek kullanıcıları da geçici olarak etkileyebilir (yanlış pozitif redler); izleme (monitoring) ile yan etkiler yakından takip edilmelidir.
* Yama production'a alındıktan hemen sonra, kalıcı fix **backlog'a değil aynı sprint'e** yazılmalıdır — aksi halde "geçici" çözüm kalıcılaşır ve unutulur.
* Her virtual patch, aynı zafiyetin geçerli olduğu **tüm alternatif uç noktalara** (export, internal, v1/v2, bulk endpoint'leri) da uygulanmalıdır; tek bir yol kapatılıp diğerleri unutulursa açık aslında kapanmamış olur.

---

## Kalıcı Çözümler

**HTTP/Yönlendirme Katmanı:** Proxy ve backend'in path parsing davranışları standartlaştırılmalı; tüm katmanlar arasında **tek bir kaynaktan gelen, normalize edilmiş** path/header seti kullanılmalı; method override mekanizmaları production'da tamamen kapatılmalı.

**Mikro Servis Güven İlişkisi:** "İç ağdan geliyor" varsayımı asla yetkilendirme yerine geçmemeli; her servis, gelen isteğin kullanıcı rolünü **kendi içinde yeniden doğrulamalı** (zero trust); SSRF'e açık her uç nokta, private/internal IP aralıklarına giden istekleri reddetmeli; ID token ile access token'ın `typ`/`aud` claim'leri üzerinden kesin ayrımı yapılmalı.

**Token ve Kriptografi:** JWT `jku`/`jwk` gibi dışarıdan gelen anahtar referanslarına asla güvenilmemeli, sabit ve önceden tanımlı key set kullanılmalı; session state'i farklı iş akışları arasında **paylaşılmamalı**, her akışa özel, izole namespace'ler kullanılmalı; token üretiminde her zaman kriptografik olarak güvenli rastgelelik (`secrets`, `crypto.randomBytes`) tercih edilmeli.

**İş Mantığı/State Machine:** Tüm yetki kontrol fonksiyonları **fail-closed** prensibiyle yazılmalı (hata = erişim reddi); kritik state-changing işlemler atomik transaction + distributed lock ile korunmalı; çok adımlı akışlarda her adım, bir öncekinin **gerçekten backend tarafından onaylandığını** doğrulamalı, sadece adımların sırayla çağrılmış olmasına güvenilmemeli.

**API ve Veri Katmanı:** GraphQL'de sorgu derinliği/karmaşıklığı ve alias sayısı sınırlandırılmalı, rate limiting sorgu sayısına göre hesaplanmalı; ORM'e map edilen tüm girdiler **açık whitelist** (DTO) üzerinden geçmeli, ilişkisel alanlar asla doğrudan kullanıcı girdisinden atanmamalı; tüm ID/filtre alanlarında **beklenen tip kesin olarak zorlanmalı**, operatör nesneleri (`$ne`, `$gt` vb.) girdi katmanında reddedilmeli.

---

## Yaygın Senaryolar

* Proxy/backend path normalizasyon uyuşmazlığı
  `GET /api/v1/admin/..;/user` → WAF onaylar, backend admin'e yönlendirir

* HTTP method override ile filtre atlatma
  `X-HTTP-Method-Override: DELETE` (görünen metod: POST)

* SSRF üzerinden iç ağ güven ilişkisi istismarı
  `source_url=http://internal-service.local/internal/v1/privileges`

* ID token'ın access token yerine kabul edilmesi
  OIDC `typ: "ID"` token'ı → kaynak erişiminde kullanılabilir hâle gelir

* JWT `jku` ile sahte anahtar seti sızdırma
  `"jku": "https://attacker.com/.well-known/jwks.json"`

* Hata durumunda fail-open yetki kontrolü
  `GET /api/v1/orders/-1` → exception → varsayılan `return True`

* HTTP/2 multiplexing ile race condition
  Tek TCP bağlantısında 50 eşzamanlı "rol güncelleme" isteği

* State machine adımının atlanması
  `/payment` iptal edilir, doğrudan `/success` çağrılır

* GraphQL alias batching ile toplu yetkisiz mutation
  `mutation { m1: updateRole(...) m2: deleteUser(...) }`

* NoSQL operatör enjeksiyonu ile filtre çökertme
  `{"user_id": {"$ne": 1}}`

---
