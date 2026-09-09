**OAuth 2.0 / OIDC**, günümüzün kimlik doğrulama ve yetkilendirme altyapısının omurgasıdır — "Google ile giriş yap", "Sign in with Apple", kurumsal SSO (Single Sign-On) çözümlerinin neredeyse tamamı bu protokol ailesi üzerine kuruludur. Ama bu yaygınlık, aynı zamanda protokolün **en tehlikeli tarafını** oluşturur: OAuth 2.0, RFC 6749'un kendi ifadesiyle bir protokol değil, bir **"protokol iskeleti" (framework)**'dir — yani kesin bir uygulama tanımlamaz, geliştiricilere geniş bir yorumlama alanı bırakır. Bu esneklik, gerçek dünyadaki implementasyon hatalarının en büyük kaynağıdır.

Bu yazı, OAuth 1.0'ın neden terk edildiğinden başlayıp, klasik CSRF/redirect_uri zafiyetlerinden JWT kriptografik saldırılarına, oradan da PAR/RAR/JARM gibi modern RFC standartlarındaki 0-day potansiyeline, IdP chaining üzerinden hesap ele geçirmeye ve client-side prototype pollution'ın OAuth token hırsızlığına dönüşmesine kadar **uçtan uca** bir güvenlik analizi sunuyor.

---

## 1. Neden OAuth 2.0? — OAuth 1.0'ın Çöküşü

OAuth 1.0 (2007), akıllı telefon devriminden önce tasarlanmıştı ve tüm trafiğin web tarayıcısı üzerinden aktığı varsayımına dayanıyordu. Mobil uygulamalarda veya tarayıcısız cihazlarda (IoT, akıllı TV) bu akışı güvenli şekilde işletmek neredeyse imkânsızdı.

Asıl kâbus ise kriptografiydi: her HTTP isteği, istemci tarafında HMAC-SHA1 ile imzalanmak zorundaydı. Parametrelerin alfabetik sıralanması, URL encoding kuralları ve "Signature Base String" oluşturma süreci o kadar hataya açıktı ki, tek bir boşluk karakteri tüm isteği geçersiz kılabiliyordu. Ayrıca Authorization Server ile Resource Server arasındaki rol ayrımı net değildi — bu da büyük mikro servis mimarilerinde (Amazon, Google ölçeğinde) ölçeklenmeyi imkânsızlaştırıyordu.

OAuth 2.0, bu sorunları kökten çözdü: kriptografik imza zorunluluğunu kaldırıp güvenliği tamamen **TLS/HTTPS katmanına** devretti, "Bearer Token" mimarisine geçti (token'ı elinde tutan doğrudan yetkilidir — tıpkı nakit para gibi), 4 temel akış tipiyle (grant type) farklı cihaz senaryolarını destekledi, ve Refresh Token kavramıyla kullanıcıyı rahatsız etmeden arka planda token yenilemeyi mümkün kıldı.

**Ama bu esnekliğin bedeli ağırdır:** OAuth 2.0'ın kriptografik imza zorunluluğunu kaldırması ve protokolü "framework" seviyesinde bırakması, bugün konuşacağımız SSRF, token hırsızlığı, state manipülasyonu gibi zafiyetlerin neredeyse tamamının kök nedenidir — protokolün kendisi değil, **geliştiricilerin bu esnekliği yanlış yapılandırması.**

---

## 2. Temel Mimari: Aktörler, Akışlar, Token'lar

### 2.1 Dört Aktör

* **Resource Owner:** Verinin sahibi — genellikle son kullanıcı.
* **Client:** Kaynağa erişmek isteyen uygulama (web app, mobil app, SPA).
* **Authorization Server (AS):** Kimlik doğrulayan ve token üreten sunucu.
* **Resource Server (RS):** Korunan verinin bulunduğu API.

### 2.2 Grant Type'lar (Akış Tipleri)

* **Authorization Code Grant + PKCE:** Modern standart. Kullanıcı AS üzerinde login olur, bir `code` alınır, bu `code` backend'de `access_token`'a çevrilir. PKCE (`code_challenge`/`code_verifier`), authorization code'un araya girilerek çalınmasına karşı ek bir kriptografik doğrulama katmanı ekler.
* **Implicit Grant:** Token doğrudan URL fragment'ında (`#access_token=...`) döner — tarayıcı geçmişinde, `Referer` header'ında ve loglarda sızma riski çok yüksek olduğu için **artık güvensiz kabul edilir.**
* **Client Credentials Grant:** Kullanıcı olmadan, servisin kendi kimliğiyle (server-to-server) token alması.
* **Password Grant (Resource Owner Password Credentials):** Kullanıcı adı/şifrenin doğrudan client'a verilmesi — kullanımdan kaldırılmıştır, çünkü client'a şifreyi görme yetkisi vermek OAuth'un temel felsefesine aykırıdır.

### 2.3 Token Tipleri

* **Access Token:** Kaynağa erişim yetkisi taşır, genellikle kısa ömürlüdür.
* **Refresh Token:** Yeni bir access token almak için kullanılır, uzun ömürlüdür ve **çalınması en kritik sonucu doğurur.**
* **ID Token (OIDC ile gelir):** Kullanıcının **kimliğini** taşıyan bir JWT — access token'dan farklı olarak "bu kaynağa eriş" değil, "bu kişi budur" bilgisini içerir. Bu ayrımı karıştırmak (bkz. Bölüm 8) tek başına ciddi bir zafiyet sınıfıdır.

---

## 3. Klasik ve Bilinen Zafiyetler (1-Day Seviyesi)

0-day aramadan önce, "1-day" seviyesindeki klasik zafiyetlerde ustalaşmak gerekir — çünkü ileri seviye zincirlerin çoğu bu temel kalıpların üzerine inşa edilir.

### 3.1 State Parametresi İhlalleri (CSRF)

`state` parametresi, authorization isteği ile callback'i birbirine bağlayan, CSRF'e karşı koruma sağlayan rastgele bir değerdir. Kullanılmıyorsa veya session'a bağlı doğrulanmıyorsa, saldırgan **kendi hesabına ait** bir authorization code'u kurbanın tarayıcısına enjekte edip, kurbanın hesabını saldırganın üçüncü taraf kimliğine bağlatabilir (account linking saldırısı):

```
GET /oauth/callback?code=ATTACKER_OWN_CODE&state=
```

`state` doğrulanmadan kabul edilirse, kurban bilmeden **saldırganın** sosyal medya hesabını kendi profiline bağlamış olur — sonrasında saldırgan bu bağlantı üzerinden kurbanın hesabına giriş yapabilir.

### 3.2 Zayıf Redirect URI Doğrulaması

Authorization Server, `redirect_uri`'yi **tam eşleşme (exact match)** yerine gevşek (prefix/regex tabanlı) kontrol ediyorsa:

```
redirect_uri=https://victim.com.attacker.com/callback
redirect_uri=https://victim.com/callback/../../evil
redirect_uri=https://victim.com@attacker.com/
```

Bu varyasyonlar, zayıf yazılmış bir regex'i (`^https://victim\.com`) veya path traversal'a duyarlı bir string karşılaştırmasını atlatarak authorization code'un **saldırganın domain'ine** yönlendirilmesini sağlayabilir.

### 3.3 Token Sızıntı Kanalları

* **`Referer` header'ı:** Callback sayfası, token'ı URL'de taşıyorsa (implicit grant) ve sayfa üçüncü taraf bir kaynağa (analytics, reklam) istek atıyorsa, token `Referer` header'ı üzerinden o üçüncü tarafa sızar.
* **Tarayıcı geçmişi:** URL'de taşınan token'lar, tarayıcı geçmişinde kalıcı olarak saklanır.
* **`window.opener`:** Callback sayfası bir popup içinde açılmışsa ve `window.opener` referansı temizlenmemişse, popup'ı açan orijinal sayfa (eğer XSS'e açıksa) `window.opener.location` üzerinden callback URL'sindeki token'a erişebilir.

### 3.4 PKCE Downgrade

PKCE, mobil/SPA uygulamalarda authorization code'un araya girilerek (özellikle aynı cihazdaki başka bir zararlı uygulama tarafından) çalınmasına karşı koruma sağlar — `code_verifier` olmadan `code`, `access_token`'a çevrilemez. Ancak Authorization Server, PKCE'yi **zorunlu kılmıyorsa** (opsiyonel bırakıyorsa), saldırgan PKCE parametrelerini isteğinden tamamen çıkararak eski, korumasız akışa geri döner (downgrade) — bu, "güvenli mod var ama zorunlu değil" tasarımının klasik sonucudur.

---

## 4. JWT Güvenliği — Derinlemesine

OIDC doğrudan JWT tabanlı çalıştığı için, JWT'nin kriptografik ve mantıksal zafiyetleri OAuth güvenliğinin ayrılmaz bir parçasıdır.

### 4.1 Algoritma Karışıklığı (Algorithm Confusion)

Sunucu RS256 (asimetrik: private key ile imzala, public key ile doğrula) bekliyor ama doğrulama kodu **hem RS256 hem HS256'yı** kabul edecek şekilde yazılmışsa, saldırgan herkese açık olan **public key'i**, HS256'nın simetrik secret'ı olarak kullanarak sahte bir token imzalayabilir:

```python
import jwt
public_key = open("as_public_key.pem").read()
forged = jwt.encode({"sub": "victim", "role": "admin"}, public_key, algorithm="HS256")
```

Sunucu, "HS256 ile imzalanmış, ve secret olarak elimdeki public key ile doğrulanıyor — geçerli!" diyerek bu sahte token'ı kabul eder.

### 4.2 `none` Algoritması

```json
{"alg": "none", "typ": "JWT"}
```

İmza doğrulaması `alg` header'ına göre koşullu çalışıyorsa ve `none` durumu ayrıca reddedilmiyorsa, saldırgan imzasız bir token üretip claim'lerini (rol, kullanıcı ID) dilediği gibi değiştirebilir.

### 4.3 JWKS Enjeksiyonu (`jku`/`x5u`)

Token header'ındaki `jku` (JWK Set URL) veya `x5u` (X.509 sertifika URL'si), doğrulama anahtarının **nereden** çekileceğini belirtir. Sunucu bu URL'yi whitelist yapmadan kullanıyorsa, saldırgan kendi sunucusunda barındırdığı sahte bir anahtar setini `jku` olarak gösterip, **kendi ürettiği anahtarla imzaladığı** token'ı geçerli kabul ettirebilir.

### 4.4 Kriptografik Olmayan Girdi Doğrulama Eksiklikleri

`exp` (süre sonu), `nbf` (not-before) ve `aud` (hedef kitle) claim'lerinin sunucu tarafından kontrol edilmemesi de en az imza atlatma kadar tehlikelidir:

* `exp` kontrol edilmiyorsa, süresi dolmuş bir token sonsuza kadar geçerli kalır.
* `aud` kontrol edilmiyorsa, **A servisi için üretilmiş** bir token, **B servisinde** de kabul edilebilir hale gelir — bu, ileride göreceğimiz cross-tenant/cross-app saldırıların temelidir.

---

## 5. JWKS `kid` Enjeksiyonu — İleri Seviye Kriptografik Sabotaj

`kid` (Key ID), token'ın **hangi anahtarla** doğrulanacağını belirten bir header alanıdır. Sunucu, gelen `kid` değerini alıp **arka planda bir veritabanından veya dosya sisteminden** ilgili anahtarı çekiyorsa, bu değer aslında **kullanıcı kontrollü bir girdi** haline gelir:

```json
{"alg": "HS256", "kid": "' UNION SELECT 'attacker_known_secret' -- "}
```

```json
{"alg": "HS256", "kid": "../../../../dev/null"}
```

`kid` değeri doğrudan bir SQL sorgusuna birleştiriliyorsa, saldırgan **SQL Injection** ile sorgunun her zaman kendi bildiği bir secret'ı döndürmesini sağlayabilir. `kid` bir dosya yolu olarak kullanılıyorsa, `../../../../dev/null` gibi bir path traversal, sistemin **boş bir dosyayı** anahtar olarak okumasına yol açabilir — boş string ile imzalanmış bir HMAC token, doğrulamayı geçer çünkü sunucu da aynı "boş" anahtarla doğrulama yapmaktadır.

---

## 6. ECDSA Nonce Reuse / Zayıf Rastgelelik

Authorization Server, token imzalamak için ECDSA (örneğin `ES256`) kullanıyorsa, her imza işleminde **bir kerelik rastgele bir değer** (`k` parametresi, nonce) üretilir. Bu değer:

* **Tekrar ederse** (aynı `k` iki farklı imzada kullanılırsa), veya
* **Zayıf/tahmin edilebilir** bir PRNG'den türetiliyorsa,

saldırgan, aynı `k` ile imzalanmış **iki farklı token'ın** imza değerlerini matematiksel olarak karşılaştırarak, Authorization Server'ın **private key'ini** deşifre edebilir. Bu, ECDSA'nın temel matematiksel özelliğinden kaynaklanır: `k` bilindiğinde veya iki imza aynı `k`'yı paylaştığında, doğrusal denklem sistemi private key için çözülebilir hale gelir. Bu saldırı sınıfı literatürde iyi bilinir (örneğin Sony PS3'ün imzalama anahtarının bu şekilde sızdırılması), ve modern OAuth provider'larında **ECDSA implementasyonunun rastgelelik kaynağı** kritik bir denetim noktasıdır.

---

## 7. Session Puzzle ve Hibrit Akış Yarış Durumları

Modern web mimarileri (Next.js, Nuxt) frontend/backend arasında session senkronizasyonu için hibrit çözümler kullanır — bu asenkron yapı, klasik race condition'lara zemin hazırlar.

### 7.1 Authorization Code Redirection Race Condition

`response_type=code id_token` gibi hibrit akışlarda, Authorization Server hem `code` hem `id_token`'ı aynı anda döner. Teorik olarak `code` **tek kullanımlıktır** — backend, code'u işleyip "kullanıldı" olarak işaretler. Ama bu işaretleme işlemi ile code'un doğrulanması arasında bir zaman penceresi varsa, aynı `code` ile **eşzamanlı olarak** birden fazla HTTP isteği gönderilebilir:

```python
import httpx, asyncio

async def redeem_code(client, code):
    return await client.post("https://as.target.com/token",
        data={"grant_type": "authorization_code", "code": code})

async def race():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [redeem_code(client, "STOLEN_CODE") for _ in range(20)]
        results = await asyncio.gather(*tasks)
```

"Kullanıldı" kontrolü henüz veritabanına yazılmadan gelen paralel isteklerin bir kısmı, **aynı authorization code'dan birden fazla geçerli session** üretebilir — bu, tek bir çalınmış code'un normalde tek bir oturuma dönüşmesi gerekirken, saldırganın **kendi** oturumunu da eş zamanlı olarak açabilmesine imkân tanır.

### 7.2 Front-Channel Logout Desenkronizasyonu

Kurumsal SSO mimarilerinde, ana IdP oturumu kapattığında bağlı tüm uygulamalara (Relying Party) iframe üzerinden (front-channel) veya sunucudan sunucuya (back-channel) logout isteği gönderir. Saldırgan, kurbanın tarayıcısındaki bu front-channel logout isteklerini **ağ seviyesinde engelleyebilir** veya tarayıcı kısıtlamalarını (örneğin üçüncü taraf cookie/SameSite blokajlarını) istismar ederek iframe'in logout isteğini gerçekten tamamlamasını engelleyebilir. Sonuç: kullanıcı ana IdP'den çıkış yaptığını düşünürken, **bağlı alt uygulamalardaki oturumu** aslında hâlâ açık kalır — özellikle paylaşımlı/ortak cihazlarda ciddi bir hesap ele geçirme riski oluşturur.

---

## 8. Cross-Tenant ve IdP Chaining Saldırıları

### 8.1 Issuer (`iss`) Karışıklığı ile Tenant İzolasyonu Atlatma

Multi-tenant OIDC mimarilerinde (her müşteriye ayrı bir "tenant" tahsis eden SaaS ürünleri), uygulama gelen ID Token'daki `iss` (issuer) claim'ini doğrular — ama imza doğrulama anahtarını (JWKS URL) **global/ortak bir havuzdan** çekiyorsa, kritik bir tutarsızlık oluşur:

```json
{ "iss": "https://idp.target.com/tenant/attacker-tenant", "sub": "1044", "email": "victim@company.com" }
```

Saldırgan **kendi tenant'ında** (kendi kontrolündeki, geçerli bir hesapta) bir token üretir, ama bu token'ın imzası **ortak JWKS havuzundan** doğrulandığı için geçerli sayılır. Eğer uygulama, hangi tenant'a ait olduğunu sadece `iss` claim'ine bakarak değil de **kullanıcı e-postasına** göre eşliyorsa (bkz. Bölüm 8.3), saldırgan kendi tenant'ında kurbanın e-postasıyla bir profil oluşturarak **kurbanın hesabına** giriş yapabilir.

### 8.2 IdP Chaining ve Claim Shadowing

Bir sistem "Google ile giriş yap" gibi görünse de arka planda kendi Okta/Keycloak mimarisini çalıştırıyor ve bu da başka bir alt sisteme federe oluyorsa (**IdP chaining**), zincirin **en zayıf halkası** belirleyici olur.

**Senaryo:** Saldırgan, zincirin en altındaki (güvenilmeyen veya kendisinin işlettiği) bir IdP'de, kurbanın e-posta adresine sahip sahte bir profil açar. Zincirleme kimlik doğrulama sırasında üst katmandaki IdP'ler, gelen claim'leri (`email_verified: true` gibi) **"zaten alt zincir doğruladı"** varsayımıyla sorgusuz kabul eder — ama alt zincirdeki IdP bu doğrulamayı hiç yapmamıştır, sadece claim'i "iddia etmiştir". Sonuç: hedef sistemde **tam hesap ele geçirme.**

### 8.3 `sub` Yerine `email` Claim'ine Güvenme

IdP'nin sağladığı **benzersiz ve değişmez** kimlik `sub` claim'idir — `email` ise değişebilir, ve bazı IdP'lerde yeniden kullanılabilir (bir kullanıcı hesabını silip aynı e-postayla yeni bir hesap açabilir). Uygulama hesap eşlemesini `sub` yerine `email` üzerinden yapıyorsa, saldırgan **kurbanın eski/silinmiş e-posta adresini** kendi yeni hesabına kaydettirip, o hesapla giriş yaparak kurbanın **eski verisine** erişebilir. Bu kalıp, "Sign in with Apple" ekosisteminde geçmişte gerçek bir 0-day olarak rapor edilmiştir.

### 8.4 Dynamic Client Registration (DCR) ile Client Impersonation

Sistem açık kayıt (open registration, RFC 7591) destekliyorsa, saldırgan kendi sahte client'ını kaydedebilir. Kayıt metadata'sındaki `grant_types` veya `token_endpoint_auth_method` gibi parametrelerle oynayarak, sahte client'ın Authorization Server tarafından **ana/güvenilir client'a** benzer şekilde davranmasını sağlamaya çalışabilir — özellikle client eşlemesi zayıf yazılmış bir sistemde, bu "kimlik taklidi" ciddi bir güven ihlaline dönüşür.

### 8.5 Back-Channel İsteklerinde Parametre Kirliliği

OAuth sunucusunun kendi iç mikroservisleriyle konuştuğu back-channel istekleri (`/token`, `/userinfo` endpoint'leri), istemci tarafından gönderilen parametrelerle **birebir** oluşturuluyorsa, HTTP Parameter Pollution ile ek bir `client_id` sızdırılabilir:

```
POST /token
grant_type=authorization_code&code=xxx&client_id=attacker&client_id=victim
```

Sunucunun iç bileşenleri bu iki `client_id` değerinden **farklısını** okuyorsa (örn. ilk gateway ilkini, backend ikincisini), işlem yanlış client bağlamında (kurbanın client'ı) gerçekleştirilebilir.

---

## 9. Modern RFC Standartlarında 0-Day Potansiyeli

### 9.1 JARM (JWT Secured Authorization Response Mode) — Padding Oracle

JARM (Financial-grade API / RFC 9101 ailesi), tarayıcı üzerinden dönen `code`/`state` parametrelerinin manipülasyonunu engellemek için, authorization response'unu **şifreli ve imzalı bir JWT** olarak döndürür. Ama provider'ın kullandığı şifreleme kütüphanesi, geçersiz bir `enc`/`alg` parametresine sahip bir JARM isteği aldığında hatayı işlerken **ölçülebilir zaman farkları** yaratıyorsa (klasik bir padding oracle senaryosu), saldırgan bu zamanlama farklarından yararlanarak şifreli yanıtın (ve dolayısıyla içindeki gizli `code` değerinin) içeriğini **adım adım deşifre edebilir.**

### 9.2 PAR (Pushed Authorization Requests) — Cache Poisoning ve DoS

PAR (RFC 9126), yetkilendirme parametrelerinin URL yerine doğrudan back-channel POST isteğiyle gönderilmesini ve karşılığında kısa ömürlü bir `request_uri` alınmasını sağlar — bu istek kullanıcı **henüz login olmadan** gerçekleşir.

**PAR Request Smuggling / Cache Poisoning:** PAR endpoint'inin önünde genellikle bir reverse proxy/WAF (Nginx, CloudFront) bulunur. HTTP Request Smuggling teknikleriyle (bkz. Load Balancer yazımızdaki CL.TE/TE.CL detayları) bu proxy atlatılarak PAR endpoint'ine hileli parametreler enjekte edilebilir. Provider bu parametreleri Redis/memory önbelleğe yazarsa, kurban login olduğunda **kirletilmiş PAR verisiyle** (saldırganın `redirect_uri`'siyle) yetkilendirilmiş olur.

**Memory Exhaustion / RCE via Unauthenticated PAR:** Kimlik doğrulaması yapılmamış isteklerle devasa büyüklükte (derin nested JSON içeren) PAR talepleri gönderilerek, provider'ın iç önbellek/serileştirme mekanizmasında DoS veya (insecure deserialization varsa) doğrudan RCE tetiklenebilir.

### 9.3 RAR (Rich Authorization Requests) — JSON Parsing Collision

RAR (RFC 9396), klasik scope mantığının yetmediği ince ayarlı yetkiler için (`authorization_details` JSON objesi) kullanılır:

```json
"authorization_details": {
  "type": "payment_initiation",
  "actions": ["initiate"],
  "locations": ["https://bank.com"]
}
```

Provider bu JSON'u parse edip onay ekranında gösterirken ve veritabanına işlerken filtrelemiyorsa, **çakışan (duplicate) anahtarlar** göndererek bir "shadowing" saldırısı yapılabilir:

```json
{
  "actions": ["read"],
  "some_other_field": "...",
  "actions": ["admin_transfer"]
}
```

JSON parser'lar duplicate key'lerde genellikle **son değeri** kabul eder — ama onay ekranını render eden kod ile veritabanına yazan kod **farklı parser'lar** kullanıyorsa (biri ilkini, diğeri sonuncusunu alıyorsa), kullanıcıya zararsız görünen bir izin (`read`) onaylatılırken, arka planda **gerçekte kaydedilen** yetki çok daha geniş (`admin_transfer`) olabilir.

### 9.4 DCR Üzerinden SSRF/RCE Zinciri

Dynamic Client Registration sırasında gönderilen `logo_uri`, `jwks_uri`, `policy_uri` gibi parametreler, provider sunucusu tarafından **işlenir.**

**Blind SSRF:** Provider, `jwks_uri`'ye giderek client'ın public key'lerini çekmeye çalışırken, saldırgan bu adresi iç ağdaki bir servise (`http://169.254.169.254/`, iç Kubernetes API'si) yönlendirebilir.

```json
{ "client_name": "evil-client", "jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```

**Görsel İşleme Üzerinden RCE:** `logo_uri`'ye verilen bir SVG/imaj dosyası, provider'ın arkadaki görsel işleme kütüphanesi (ImageMagick gibi, geçmişte "ImageTragick" olarak bilinen zafiyetler) tarafından işlenirken, kütüphanenin kendi zafiyetleri üzerinden sunucuda **doğrudan kod çalıştırma** elde edilebilir.

---

## 10. Multi-Protocol Identity Confusion (OAuth ↔ SAML/LDAP)

Birçok kurumsal Identity Provider, sadece OAuth/OIDC değil, arkada SAML veya Active Directory/LDAP gibi eski protokollerle de köprü (federation) kurar. XML tabanlı SAML yanıtları ile JSON tabanlı JWT/OIDC yanıtlarının **dönüştüğü nokta** (identity broker), protokoller arası en zayıf halkadır.

SAML tarafında yapılan bir **XXE (XML External Entity)** veya **SAML Response Smuggling** (imza kapsamının dışında bırakılan bir elementin manipüle edilmesi — signature exclusion) saldırısı, identity broker'ın kafasını karıştırarak, saldırgana **teknik olarak kusursuz görünen bir OIDC Access Token'ı** ürettirebilir. Bu, iki farklı protokolün güven modelinin **tek bir dönüşüm katmanında** birleştiği her noktada araştırılması gereken kritik bir saldırı yüzeyidir.

---

## 11. Client-Side Prototype Pollution → OAuth Token Hırsızlığı

Bu, tamamen SPA mimarilerini (React, Angular, Vue) hedef alan modern bir zincirleme saldırıdır ve [Prototype Pollution yazımızda](#) detaylandırdığımız temellere dayanır.

Uygulamadaki bir client-side JavaScript prototype pollution zafiyeti kullanılarak, tarayıcıdaki global `Object.prototype` kirletilir. OAuth istemci kütüphaneleri (`oidc-client-js`, `msal.js`), token'ı bellekte veya `localStorage`/`sessionStorage`'da işlerken **konfigürasyon nesnelerini** (`state`, `nonce`, `storageKey` gibi alanları) kullanır:

```javascript
// Kirlenme (client-side, örneğin URL fragment üzerinden)
Object.prototype.storageKey = "attacker_controlled_key";
Object.prototype.redirect_uri = "https://attacker.com/callback";
```

Eğer OAuth kütüphanesinin iç options nesnesi bu değerleri **prototipten devralıyorsa**, üretilen/alınan token'lar saldırganın belirlediği bir `storageKey`'e yazılabilir (saldırgan aynı origin'de çalışan başka bir script ile bu key'i okuyabilir) veya callback akışı saldırganın kontrolündeki bir adrese yönlendirilebilir — sonuç, **tamamen client-side bir zafiyetin**, tarayıcıdan çalınan gerçek bir OAuth access/ID token ile sonuçlanmasıdır.

---

## 12. Tespit Metodolojisi

1. **Akış haritalama:** Hedefin hangi grant type'ları desteklediğini, PKCE'nin zorunlu olup olmadığını belirle.
2. **State/redirect_uri testi:** `state` olmadan/manipüle ederek CSRF dene; `redirect_uri`'yi regex bypass varyasyonlarıyla test et.
3. **JWT saldırı yüzeyi:** `alg` header'ını `none`/`HS256` yaparak dene; `jku`/`x5u`/`kid` alanlarını manipüle et.
4. **Claim doğrulama testi:** `exp`, `nbf`, `aud` claim'lerinin gerçekten kontrol edilip edilmediğini süresi geçmiş/yanlış audience'lı token'larla doğrula.
5. **Race condition testi:** Authorization code'u HTTP/2 üzerinden paralel isteklerle "redeem" etmeyi dene.
6. **Cross-tenant testi:** Kendi tenant'ında ürettiğin token'ı başka bir tenant/uygulamada denemeyi dene (`iss`/`aud` karışıklığı ara).
7. **DCR/SSRF testi:** Açık kayıt destekleniyorsa `jwks_uri`/`logo_uri` gibi alanlara iç ağ adresleri vererek blind SSRF ara.
8. **Modern RFC testi:** PAR/RAR/JARM destekleniyorsa, bu uç noktalarda smuggling, duplicate key ve zamanlama farkı testleri yap.

---

## Virtual Patch — Acil Durum Yaması

Bir OAuth/OIDC implementasyonunda kritik bir açık tespit edildiğinde, kalıcı mimari değişiklik zaman alır. Saatler içinde uygulanabilecek acil önlemler:

**1. `state` ve `redirect_uri` için Acil Sıkılaştırma**

```python
# ✅ Acil patch: state session'a bağlı, tek kullanımlık, ve redirect_uri tam eşleşme
if request.args.get("state") != session.pop("oauth_state", None):
    return abort(403)
if request.args.get("redirect_uri") not in ALLOWED_REDIRECT_URIS:  # exact match set
    return abort(400)
```

**2. JWT Algoritmasını Acilen Sabitleme**

```python
# ✅ Acil patch: sadece beklenen algoritma kabul edilir, alg header'ına asla güvenilmez
claims = jwt.decode(token, key=KNOWN_PUBLIC_KEY, algorithms=["RS256"])  # whitelist
```

**3. `jku`/`x5u`/`kid` Alanlarına Acil Whitelist**

```python
ALLOWED_JWKS_HOSTS = {"idp.target.com"}

def validate_jku(jku_url):
    if urlparse(jku_url).hostname not in ALLOWED_JWKS_HOSTS:
        return abort(400)
```

**4. Authorization Code Redeem İşlemine Acil Distributed Lock**

```python
# ✅ Acil patch: aynı code için eşzamanlı redeem'i Redis kilidiyle engelle
if not redis.set(f"lock:code:{code}", "1", nx=True, ex=10):
    return abort(409)  # zaten işlemde
```

**5. DCR Parametrelerine Acil SSRF Filtresi**

```python
import ipaddress, socket

def is_safe_uri(uri):
    host = urlparse(uri).hostname
    ip = socket.gethostbyname(host)
    return not ipaddress.ip_address(ip).is_private

for field in ("jwks_uri", "logo_uri", "policy_uri"):
    if field in registration_data and not is_safe_uri(registration_data[field]):
        return abort(400)
```

**6. Cross-Tenant JWKS Ayrımını Acil Zorlama**

```python
# ✅ Acil patch: iss claim'ine göre DOĞRU tenant'ın JWKS'i seçiliyor, ortak havuz kullanılmıyor
tenant = extract_tenant_from_iss(claims["iss"])
jwks = get_tenant_specific_jwks(tenant)  # global havuz DEĞİL
verify_signature(token, jwks)
```

**Dikkat edilmesi gerekenler:**

* Bu önlemler geçicidir — asıl çözüm PKCE'nin zorunlu kılınması, tenant izolasyonunun mimari seviyede garanti edilmesi ve tüm claim doğrulamalarının (iss/aud/exp/nbf) merkezi bir kütüphanede standardize edilmesidir.
* Acil whitelist'ler (redirect_uri, jku host) düzenli gözden geçirilmeli — eski/artık kullanılmayan client'lara ait girişler unutulmamalı.
* Yama sonrası, halihazırda sızmış olabilecek refresh token'ların **toplu olarak iptal edilmesi (revoke)** değerlendirilmelidir.

---

## Kalıcı Çözümler

**Temel Akış Güvenliği:** PKCE tüm client tiplerinde (sadece mobil/SPA değil) zorunlu kılınmalı; `state` her zaman session'a bağlı, tek kullanımlık ve kriptografik olarak rastgele üretilmeli; `redirect_uri` sadece tam eşleşme ile doğrulanmalı.

**JWT/Kriptografi:** Algoritma whitelisting zorunlu olmalı, `alg` header'ına asla güvenilmemeli; `jku`/`x5u` gibi dışarıdan anahtar referansı alan alanlar sabit whitelist ile sınırlanmalı; ECDSA imzalama süreçlerinde rastgelelik kaynağı düzenli denetlenmeli (deterministic ECDSA — RFC 6979 — tercih edilmeli).

**Tenant İzolasyonu:** JWKS doğrulaması her zaman `iss` claim'ine göre **tenant-specific** olmalı, asla ortak/global bir havuzdan çekilmemeli; hesap eşlemesi her zaman `sub` üzerinden yapılmalı, `email` asla birincil kimlik anahtarı olarak kullanılmamalı.

**Modern RFC Uygulamaları:** PAR/RAR/JARM destekleniyorsa, bu endpoint'lerin önündeki proxy/WAF katmanı ile backend'in HTTP parsing davranışı tutarlı olmalı (smuggling'e karşı); RAR'daki `authorization_details` JSON'u tek bir kanonik parser ile işlenmeli, duplicate key'ler explicit olarak reddedilmeli.

**DCR Güvenliği:** Açık kayıt destekleniyorsa, kayıt sırasında alınan tüm URI parametreleri (jwks_uri, logo_uri, policy_uri) SSRF filtresinden geçirilmeli; görsel işleme kütüphaneleri güncel tutulmalı, mümkünse sandbox'lanmış bir ortamda çalıştırılmalı.

**İzleme:** Aynı authorization code'un birden fazla kez redeem edilme girişimleri, farklı tenant'lardan gelen ama aynı `sub`/`email`'e sahip token'lar ve DCR üzerinden iç ağ IP aralıklarına yapılan istekler için otomatik alarm kuralları tanımlanmalı.

---

## Yaygın Senaryolar

* State eksikliği ile CSRF/account linking
  `GET /oauth/callback?code=ATTACKER_CODE&state=` (doğrulama yok)

* Algoritma karışıklığı ile sahte token
  RS256 public key → HS256 secret olarak kullanılıp token imzalama

* JWKS `kid` üzerinden SQLi/path traversal
  `"kid": "../../../../dev/null"` → boş anahtarla imza doğrulama

* Authorization code race condition
  Aynı code ile 20 paralel `/token` isteği → birden fazla geçerli session

* Issuer/JWKS karışıklığı ile cross-tenant hesap ele geçirme
  Kendi tenant'ında üretilen token, ortak JWKS havuzu üzerinden başka tenant'ta geçerli sayılıyor

* IdP chaining ile claim shadowing
  Alt zincirdeki güvenilmeyen IdP'de kurbanın e-postasıyla sahte profil → üst IdP'nin `email_verified` claim'ine körü körüne güvenmesi

* DCR üzerinden blind SSRF
  `"jwks_uri": "http://169.254.169.254/latest/meta-data/..."`

* RAR'da duplicate key ile yetki shadowing
  `"actions": ["read"], ..., "actions": ["admin_transfer"]`

* Client-side prototype pollution ile token hırsızlığı
  `Object.prototype.storageKey` kirletilerek token'ın saldırgan kontrolündeki alana yazılması

---
