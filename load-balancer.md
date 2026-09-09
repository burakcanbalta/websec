<img width="1600" height="963" alt="what-is-a-load-balancer" src="https://github.com/user-attachments/assets/c6a8343d-c896-4c11-85a4-28555bec498c" />

**Load Balancer (Yük Dengeleyici)**, modern altyapının belki de en az sorgulanan bileşenidir. Herkes onu "trafiği dağıtan kutu" olarak bilir, güvenlik ekipleri genellikle onu **savunma hattının bir parçası** sanır — WAF modülü var, SSL'i o çözüyor, arkadaki sunucuları o koruyor... Oysa gerçek şu: load balancer, trafiğin **her baytının** üzerinden geçtiği, genellikle root yetkisiyle çalışan, kapalı kaynaklı ve C/C++ ile yazılmış bir ağ cihazıdır. Yani aslında bu, saldırı yüzeyinin en **kritik ve en az test edilen** noktasıdır — çünkü kimse "zaten güvenlik cihazı" dediği bir şeyi test etmeyi düşünmez.

---

## 1. Temel Kavramlar: Load Balancer Nasıl Çalışır?

Yük dengeleyici, gelen trafiği arkadaki birden fazla sunucuya (backend pool) dağıtan bir cihaz/yazılımdır. Ama güvenlik açısından asıl önemli olan, **hangi katmanda** ve **ne kadar "akıllı"** çalıştığıdır.

### Katman 4 (L4) Dengeleme

Aktarım katmanında (TCP/UDP) çalışır. Paketin içeriğine hiç bakmaz — sadece kaynak/hedef IP ve port bilgisine göre yönlendirme yapar. Bu, saldırı yüzeyini teknik olarak daraltır (HTTP semantiğiyle oynanamaz) ama görünürlüğü de düşürür: L4 bir LB, arkasında hangi HTTP isteğinin gittiğini **anlamaz**, sadece TCP akışını yönlendirir.

### Katman 7 (L7) Dengeleme

Uygulama katmanında (HTTP/HTTPS) çalışır. HTTP başlıkları, cookie'ler, URL path'leri üzerinden akıllı yönlendirme yapar (`Host: api.target.com` → API pool'u, `/static/*` → CDN pool'u gibi). Bu akıllılık, aynı zamanda saldırı yüzeyinin ta kendisidir — çünkü LB artık HTTP isteğini **parse etmek zorunda**, ve her parser'ın kendi yorumu vardır.

### SSL/TLS Termination

Şifreli (HTTPS) trafik LB üzerinde çözülür ve arkadaki sunuculara genellikle **şifresiz (HTTP)** olarak iletilir — bu, "SSL offloading" olarak bilinir ve performans için yapılır (şifre çözme işlemi CPU-yoğundur, LB'nin bunu özel donanımla yapması arkadaki sunucuları rahatlatır). Pentester açısından bu, **iki farklı protokol yorumunun aynı istekte devreye girdiği** anlamına gelir.

---

## 2. Reconnaissance ve Fingerprinting

Bir hedefte load balancer olduğunu ve markasını tespit etmek, saldırı stratejisini doğrudan belirler — çünkü F5 BIG-IP'ye özel bir teknik, HAProxy'de işe yaramaz.

### HTTP Başlıkları ve Cookie İmzaları

```http
Server: BigIP
X-SharePoint-HealthScore: 0
Set-Cookie: BIGipServerPool_HTTP=1677787402.20480.0000
```

Bu tür imzalar (`Server` header'ı, özel cookie isimlendirmeleri) markayı doğrudan ele verir:

| İmza | Ürün |
|---|---|
| `BIGipServer*` cookie | F5 BIG-IP |
| `NSC_*` cookie, `Cneonction` header | Citrix NetScaler/ADC |
| `X-Envoy-*` header | Envoy Proxy |
| `Via: 1.1 varnish` | Varnish/HAProxy kombinasyonu |

### DNS ve IP Çeşitliliği

Aynı alan adına farklı zamanlarda atılan sorguların farklı IP'ler döndürmesi (round-robin DNS) veya TTL değerlerinin anormal şekilde düşük/değişken olması, arkada bir dengeleme mekanizması olduğuna işaret eder.

### Zamanlama Tabanlı Tespit

`lbd` (Load Balancing Detector) ve `halberd` gibi araçlar, aynı isteği tekrar tekrar atıp **yanıt süresindeki mikro farkları** ve TCP zaman damgası (timestamp) tutarsızlıklarını analiz ederek, tek bir sunucu mu yoksa bir havuz mu olduğunu istatistiksel olarak çıkarır. Bu prensip ileride HTTP request smuggling tespitinde de karşımıza çıkacak — **zamanlama farkı, gizli mimariyi ele veren en güvenilir sinyaldir.**

---

## 3. HTTP Request Smuggling (İstek Kaçakçılığı)

Bu, load balancer güvenliğinin en derin ve en yıkıcı konusudur. Kök neden: **LB ile arkadaki uygulama sunucusunun (IIS, Nginx, Apache, Node.js) aynı HTTP isteğinin nerede bittiğini farklı yorumlaması.**

HTTP/1.1'de bir isteğin gövdesinin uzunluğu iki farklı header ile belirtilebilir:

* `Content-Length` (CL) — gövdenin bayt cinsinden uzunluğu
* `Transfer-Encoding: chunked` (TE) — gövde parça parça (chunk) gönderilir, her parçanın kendi uzunluğu vardır

RFC 7230, her iki header birden geldiğinde `Transfer-Encoding`'in öncelikli olmasını ve `Content-Length`'in **yok sayılmasını** söyler. Ama gerçek dünyada her sunucu bu kurala aynı titizlikle uymaz.

### CL.TE Saldırısı

Ön uç (LB) `Content-Length`'e göre, arka uç (backend) `Transfer-Encoding`'e göre davranıyorsa:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

LB, `Content-Length: 13` diyerek isteğin `0\r\n\r\n` ile bittiğini düşünür ve isteği olduğu gibi backend'e iletir. Backend ise `Transfer-Encoding: chunked`'e göre okur: `0` chunk'ı "gövde bitti" anlamına gelir, ama LB'nin bağlantıyı kapatmamış olması nedeniyle **bağlantıda kalan `SMUGGLED` verisi**, backend tarafından **bir sonraki isteğin başlangıcı** olarak yorumlanır. Bu, sıradaki kullanıcının isteğine kendi verinizi "kaçakçılıkla" eklemenize (request smuggling) yol açar — hesap ele geçirme, cache poisoning, response zehirleme gibi sonuçlar doğurabilir.

### TE.CL Saldırısı

Tam tersi: LB `Transfer-Encoding`'e, backend `Content-Length`'e göre davranıyorsa, chunk boyutunu yanlış hesaplayarak aynı mantıkla ters yönde bir kaçakçılık gerçekleştirilir.

### TE.TE Saldırısı

Her iki taraf da `Transfer-Encoding` kullanıyor gibi görünse de, header'ın **yazılış şeklindeki küçük bir bozukluk** (`Transfer-Encoding: chunked` yerine `Transfer-Encoding : chunked` — fazladan boşluk, ya da `Transfer-encoding: xchunked`) bir tarafça geçerli, diğerince geçersiz sayılabilir:

```http
Transfer-Encoding: chunked
Transfer-Encoding: cow
```

Bazı parser'lar son değeri, bazıları ilk değeri, bazıları hiçbirini geçerli saymaz — bu üçlü kombinasyon (CL.TE / TE.CL / TE.TE), günümüzde hâlâ en aktif araştırılan web güvenliği konularından biridir.

### HTTP/2 → HTTP/1.1 Downgrade Smuggling

Modern LB'ler istemciyle HTTP/2 konuşup backend'e HTTP/1.1 olarak "çevirerek" (downgrade) iletebilir. HTTP/2'de `Content-Length` ve `Transfer-Encoding` karmaşası teorik olarak yoktur (frame tabanlı, uzunluk açıkça belirtilir) — ama **downgrade işlemi sırasında** bu netlik kaybolabilir. LB, HTTP/2 isteğini HTTP/1.1'e çevirirken hatalı bir `Content-Length` hesaplarsa, aynı CL.TE mantığı HTTP/2 dünyasından sızarak yeniden ortaya çıkar. Ayrıca bazı ortamlarda istemcinin `Upgrade: h2c` header'ıyla düz metin HTTP/2'ye geçiş talep etmesi, LB'nin bu upgrade'i doğru şekilde engellememesi durumunda, **backend'e doğrudan protokol karışıklığı enjekte etme** imkânı sunar.

---

## 4. Session Cookie Çözümleme ve İç Ağ IP İfşası

F5 BIG-IP gibi cihazlar, oturum kalıcılığı (session persistence) sağlamak için istemciye şifreli **gibi görünen** ama aslında basit bir matematiksel dönüşümle üretilmiş cookie'ler verir:

```
Set-Cookie: BIGipServerPool_HTTP=1677787402.20480.0000
```

Bu değer üç parçadan oluşur ve klasik F5 kalıcılık cookie'sinde encoding şu mantığı izler: ilk sayı, backend sunucunun **little-endian** IP adresinin 32-bit tam sayı karşılığıdır, ikinci sayı ise port bilgisini taşır (`port × 2` şeklinde hesaplanan bir dönüşümle).

```python
import struct, socket

def decode_bigip_cookie(cookie_value):
    ip_part, port_part, _ = cookie_value.split('.')
    ip_int = int(ip_part)
    # Little-endian 32-bit -> IP string
    ip_bytes = struct.pack('<I', ip_int)
    ip = socket.inet_ntoa(ip_bytes)
    port = int(port_part) // 2 if int(port_part) else 0
    return ip, port

ip, port = decode_bigip_cookie("1677787402.20480.0000")
print(f"Backend: {ip}:{port}")
```

Bu tek satırlık çözümleme, saldırgana **iç ağdaki gerçek backend sunucunun IP adresini ve portunu** doğrudan verir — dışarıdan tamamen görünmez olması gereken bir mimari detayın, "rastgele görünen" bir cookie'nin içine gömülü olarak sızdığı klasik bir örnektir. Bu bilgi daha sonra WAF bypass (bkz. Bölüm 7) veya iç ağ haritalama için doğrudan kullanılabilir.

---

## 5. SSL/TLS Termination ve Header Enjeksiyonu

LB, SSL'i kendi üzerinde sonlandırıp backend'e düz HTTP ile iletirken, bağlantının aslında HTTPS olduğunu backend'e bildirmek için özel header'lar ekler:

```http
X-Forwarded-For: 203.0.113.4
X-Forwarded-Proto: https
X-Forwarded-Host: target.com
```

Backend, bu header'lara **güvenerek** kararlar alıyorsa (örneğin "eğer `X-Forwarded-Proto: https` ise güvenli kabul et, cookie'yi `Secure` flag olmadan da işle" gibi), saldırgan bu header'ları **kendi isteğinde manipüle ederek** backend'i kandırabilir — çünkü çoğu backend, bu header'ın LB tarafından mı yoksa doğrudan istemci tarafından mı eklendiğini ayırt edemez.

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Forwarded-Proto: https
```

Eğer bir IP-whitelist kontrolü `X-Forwarded-For` header'ının **son** değerine değil, **ilk** değerine bakıyorsa (LB kendi eklediği gerçek IP'yi zincire *sonradan* ekliyorsa), saldırgan bu header'a `127.0.0.1` yazarak "yerel ağdan geliyormuş" gibi görünebilir — klasik bir **IP-tabanlı erişim kontrolü atlatma** senaryosu.

### Host Header Injection ile İç Ağ Erişimi

LB, `Host` header'ına göre hangi backend pool'a yönlendireceğine karar veriyorsa ve bu değeri doğrulamıyorsa, saldırgan `Host` header'ını manipüle ederek **normalde erişilemeyen bir iç servise** (staging ortamı, admin paneli) yönlendirme yaptırabilir:

```http
GET / HTTP/1.1
Host: internal-admin.target.local
```

---

## 6. Path Normalization ve Kimlik Doğrulama Atlatma

LB'nin URL'deki `/abc/../def`, `;`, `%00`, `%2f` gibi karakterleri **nasıl temizlediği (normalize ettiği)**, backend'in aynı karakterleri nasıl temizlediğinden farklıysa, bu fark doğrudan **Auth Bypass 0-day'lerine** dönüşür.

**Tarihsel örnek — CVE-2020-5902 (F5 BIG-IP RCE):** F5'in TMUI (Traffic Management User Interface) yönetim panelinde, URL'nin sonuna eklenen belirli path segmentleri, kimlik doğrulama kontrolünü atlatarak doğrudan yönetimsel Java/Tcl fonksiyonlarına erişim sağlıyordu — path normalizasyonundaki bir tutarsızlık, kimlik doğrulaması olmadan **root yetkisiyle** komut çalıştırmaya kadar uzanıyordu.

```
GET /tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
```

`..;` kalıbı, bazı Java tabanlı sunucularda (Tomcat) matrix parametresi olarak yorumlanıp path traversal filtrelerini atlatabiliyordu — LB seviyesinde bu path zararsız görünürken, backend'in Java işleyicisi tamamen farklı bir noktaya ulaşıyordu.

**Modern 0-day stratejisi:** Yönetim panellerinin API endpoint'lerini fuzzing ile taramak, özellikle **URL encode edilmiş path traversal** kombinasyonlarını (`%2e%2e%2f`, çift encode `%252e%252e%252f`, Unicode normalizasyon farkları) hem LB hem backend'e ayrı ayrı göndererek yanıt farklarını karşılaştırmak.

---

## 7. Mimariden Sızma: WAF Bypass via Direct-to-Origin

Load balancer'ın WAF (Web Application Firewall) modülü aktifse, tüm koruma **trafiğin LB üzerinden geçmesine bağımlıdır.** Saldırgan, arkadaki gerçek sunucunun IP adresini öğrenirse (Bölüm 4'teki cookie çözümlemesi, DNS geçmişi kayıtları — SecurityTrails/crt.sh üzerinden eski A kayıtları, veya SSRF ile iç ağ taraması), **doğrudan o IP'ye** istek atarak WAF'ı tamamen devre dışı bırakabilir:

```
GET /admin HTTP/1.1
Host: target.com
```

```bash
curl -H "Host: target.com" https://203.0.113.55/admin --insecure
```

Backend sunucu, `Host` header'ı doğru geldiği için isteği normal karşılar — çünkü kendisi hiçbir zaman "ben sadece LB'den istek almalıyım" diye bir kontrol yapmamıştır. Bu, load balancer'ın **koruma** değil sadece **yönlendirme** sağladığı, gerçek erişim kontrolünün backend'de olması gerektiği gerçeğinin en net kanıtıdır.

---

## 8. Yönetim Arayüzleri ve Kimlik Doğrulama Atlatma

Yük dengeleyicilerin yönetim panelleri (Web UI, SSH, API) genellikle Linux tabanlı, root yetkisiyle çalışan ayrı bir kontrol düzlemidir (control plane) ve çoğu zaman **veri düzleminden (data plane) daha az test edilir** — çünkü "zaten iç ağda, dışarıya kapalı" varsayılır.

**Tarihsel ders — CVE-2019-19781 (Citrix ADC):** Citrix NetScaler ADC/Gateway'lerdeki bir path traversal açığı, kimlik doğrulaması olmadan yönetim arayüzü üzerinden dosya okuma ve nihayetinde kod çalıştırma imkânı veriyordu:

```
GET /vpn/../vpns/cfg/smb.conf HTTP/1.1
Host: target.com
```

Bu iki CVE'nin (F5 CVE-2020-5902, Citrix CVE-2019-19781) ortak paydası dikkat çekicidir: **her ikisi de path traversal + auth bypass kombinasyonundan doğmuştur** — LB üreticileri, kendi yönetim panellerini genellikle standart web güvenliği pratiklerinin dışında, "zaten sadece adminler erişir" varsayımıyla geliştirir.

**0-day arama stratejisi:** Yönetim portlarındaki (genellikle 443, 8443, 9090 gibi alternatif portlarda barındırılan) API endpoint'lerini fuzzing ile keşfetmek, her endpoint için **auth header'ı olmadan** doğrudan istek atıp yanıt kodu/süresi farkını gözlemlemek, ve path traversal payload varyasyonlarını (encode edilmiş, çift encode edilmiş, Unicode normalize edilmiş) sistematik olarak denemek.

---

## 9. Bellek Yolsuzlukları (Memory Corruption) ve Protokole Duyarlı Fuzzing

Load balancer'lar trafiği çok yüksek hızda işlemek zorunda olduğundan, paket işleme motorları neredeyse her zaman **C/C++ ile yazılmış özel (custom) kod** içerir — bu da onları klasik bellek tabanlı açıklara (buffer overflow, integer overflow, use-after-free, format string) açık hale getirir.

### Neden Network Fuzzing Yetersizdir?

Cihazın açık portlarına rastgele bayt göndermek (blind network fuzzing) çoğunlukla protokol seviyesindeki ilk kontrol noktasında (örneğin geçersiz bir HTTP başlangıç satırı) elenir ve gerçek paket işleme motoruna hiç ulaşmaz. Bunun yerine **protokole duyarlı (protocol-aware) fuzzing** gerekir: HTTP, TLS handshake veya cihaza özgü (proprietary) protokolün gramerini bilen bir fuzzer, "geçerli görünen ama sınır değerlerde bozuk" girdiler üretir.

```
# Protokole duyarlı fuzzing mantığı (kavramsal)
AFL++ / Boofuzz / LibFuzzer ile:
  - Geçerli bir HTTP isteği şablonu tanımla
  - Content-Length, chunk size, header sayısı gibi alanları
    mutasyona uğrat (integer overflow sınırlarını hedefle)
  - Coverage-guided fuzzing ile hangi mutasyonun yeni kod
    yollarına ulaştığını izle
```

**Hedeflenecek zafiyet sınıfları:**

* **Heap Overflow:** Chunk boyutu hesaplamasında işaretli/işaretsiz tam sayı karışıklığı (signed/unsigned confusion) yüzünden ayrılan bellekten daha fazla veri yazılması.
* **Integer Overflow:** `Content-Length` veya chunk boyutu alanına `4294967296` (2^32) gibi bir değer verilmesi, 32-bit bir sayaçta taşmaya (wraparound) yol açıp beklenenden çok daha küçük bir buffer ayrılmasına neden olabilir.
* **Use-After-Free (UAF):** Bağlantı yeniden kullanımı (keep-alive/connection pooling) sırasında, bir isteğin işlenmesi bitmeden ilişkili bellek yapısının serbest bırakılması ve sonraki isteğin bu "serbest" belleğe erişmesi.
* **Format String:** Log/hata mesajı üretiminde kullanıcı girdisinin doğrudan format string olarak kullanılması (`printf(user_input)` gibi) — eski ama hâlâ karşımıza çıkan bir kalıp.

Bu tür açıklar cihazı çökertebilir (DoS) veya doğrudan uzaktan kod çalıştırmaya (RCE) kadar uzanabilir — ve genellikle **kimlik doğrulama gerektirmeden**, çünkü paket işleme motoru, kimlik doğrulama katmanından **önce** devreye girer.

---

## 10. Firmware Analizi ve Tersine Mühendislik

Kurumsal load balancer'lar (F5, Citrix) açık kaynaklı değildir — donanım veya sanal cihaz (virtual appliance) olarak satılır. Bu "kara kutu"yu anlamanın yolu tersine mühendislikten geçer.

### Firmware Çıkarma

Üreticinin yayınladığı güncelleme dosyaları (`.iso`, `.ova`, `.bin`) genellikle katmanlı bir dosya sistemi (squashfs, ext4) içerir:

```bash
binwalk -e firmware_update.bin
```

`binwalk`, dosya içindeki gömülü dosya sistemlerini, sıkıştırılmış imgeleri ve dizin yapılarını otomatik olarak tespit edip çıkarır. Bazı üreticiler bu imgeleri şifreler — bu durumda önce şifreleme anahtarının nasıl türetildiğini (genellikle cihazın bootloader'ında veya önceki bir firmware sürümünde sabit kodlanmış) bulmak gerekir.

### Statik Analiz

Cihazın trafiği işleyen ana motoru — F5'te **TMM (Traffic Management Microkernel)**, Citrix'te **NSPPE (NetScaler Packet Processing Engine)** — genellikle dev boyutlu, C/C++ ile yazılmış tekil bir binary'dir. IDA Pro veya Ghidra ile bu binary'nin:

* HTTP parser fonksiyonlarını (genellikle `parse_header`, `chunk_decode` gibi isimlerle veya bu işlevi gören isimsiz fonksiyon imzalarıyla),
* Sınır kontrolü (bounds checking) yapılmayan bellek kopyalama çağrılarını (`memcpy`, `strcpy` benzeri özel implementasyonlar),
* ve kimlik doğrulama kontrol noktalarını

haritalamak, hem bilinen CVE'lerin kök nedenini anlamak hem de benzer kalıp taşıyan **yamanmamış** kod yollarını (variant analysis) bulmak için kullanılır.

### Dinamik Analiz

Sanal bir LB imajı kurup (çoğu üretici test/değerlendirme amaçlı sanal appliance sunar), işletim sistemine root olarak bağlanıp trafiği işleyen process'e `gdb` bağlamak, gerçek zamanlı bellek durumunu (memory layout) ve fuzzing sırasında oluşan çökmelerin (crash) tam olarak hangi fonksiyonda gerçekleştiğini gözlemlemeyi sağlar. Statik analizle bulunan şüpheli kod yolları, dinamik analizle **doğrulanır**.

---

## 11. Yönetim Panelleri, iRules/Tcl ve Modern Filtre Dilleri

Çoğu load balancer'ın yönetim paneli (control plane) aslında ayrı bir web uygulamasıdır — Go, Python, Java, Lua veya PHP ile yazılmıştır ve **kendi başına klasik web zafiyetlerine** (SQL injection, insecure deserialization, SSRF) açıktır. Trafik yönlendirme kuralları ise genellikle ayrı bir betik dilinde tanımlanır.

### iRules (F5) — Tcl Enjeksiyonu

F5 BIG-IP'de trafik yönlendirme mantığı **iRules** adı verilen Tcl script'leriyle tanımlanır. Eğer bir iRule, kullanıcı girdisini (örneğin bir header değerini) doğrudan bir Tcl komutuna besliyorsa:

```tcl
# ❌ Riskli: kullanıcı girdisi doğrudan eval ediliyor
set user_header [HTTP::header "X-Custom-Data"]
eval $user_header
```

Saldırgan, `X-Custom-Data` header'ına Tcl komut enjeksiyonu yaparak **LB'nin trafik işleme motoru içinde** kod çalıştırabilir — bu, klasik bir web uygulamasındaki template injection'ın (SSTI) load balancer dünyasındaki karşılığıdır.

### Lua ve WebAssembly (Envoy, Kong, Nginx)

Bulut-native ortamlarda (Kubernetes, AWS) kullanılan modern LB/API Gateway'ler (Envoy, Kong, Nginx+Lua) genellikle **Lua script'leri** veya **WebAssembly (Wasm) filtreleri** ile genişletilir:

```lua
-- ❌ Riskli: Kong/OpenResty Lua filtresi, girdiyi doğrulamadan kullanıyor
local user_id = ngx.req.get_headers()["X-User-Id"]
local query = "SELECT * FROM users WHERE id = " .. user_id
```

Bu filtrelerin belleği nasıl yönettiği (Lua'nın garbage collector'ı ile C tabanlı Nginx worker'ı arasındaki sınır) ve girdi doğrulamasını nasıl yaptığı, hem klasik enjeksiyon açıklarına hem de (Wasm modüllerinde) bellek sınır ihlallerine yol açabilir — çünkü Wasm modülleri teorik olarak sandbox'lanmış olsa da, sandbox'ın **host fonksiyonlarına** (Wasm'ın çağırabildiği dış fonksiyonlar) verdiği erişim genellikle yetersiz denetlenir.

---

## 12. Kriptografi ve TLS Sonlandırma Hataları

Load balancer'lar şirketin SSL/TLS özel anahtarlarını doğrudan tutar ve tüm trafiği çözer — kriptografik implementasyon hataları burada **en kritik** sonuçları doğurur.

### Donanım Hızlandırıcılar (ASIC/FPGA)

Büyük ölçekli LB'ler, şifre çözme işlemini CPU'ya yük bindirmemek için özel donanım kartları (ASIC/FPGA tabanlı kriptografik hızlandırıcılar) kullanır. Bu kartların sürücülerinde veya kullandıkları özelleştirilmiş TLS kütüphanelerinde (genellikle OpenSSL'in üreticiye özel çatalları/fork'ları) bulunan açıklar, standart OpenSSL'de yamanmış bir zafiyetin (Heartbleed'in varyantları gibi) **donanım implementasyonunda hâlâ mevcut** olmasına yol açabilir — çünkü donanım güncellemeleri yazılım güncellemelerinden çok daha yavaş ve nadir yapılır.

**Zamanlama Saldırıları (Timing Attacks):** Donanım hızlandırıcının şifre çözme süresi, girdiye bağlı olarak (constant-time olmayan bir implementasyon varsa) ölçülebilir farklılıklar gösterebilir — bu fark, istatistiksel analiz ile özel anahtarın bitlerini yavaş yavaş sızdırmak için kullanılabilir.

### Session Resumption ve Ticket Manipülasyonu

TLS oturum devam ettirme (session resumption), tam bir handshake'i tekrarlamamak için bir "session ticket" kullanır — bu ticket, sunucunun kendi anahtarıyla şifrelenmiş oturum durumunu istemciye taşır.

```
NewSessionTicket → istemci saklar → bir sonraki bağlantıda sunar
```

Eğer bu ticket'ları şifrelemek için kullanılan anahtar (**session ticket key**) LB cluster'ındaki tüm node'lar arasında **paylaşılıyor ve nadiren rotate ediliyorsa**, bir node'un ele geçirilmesi, geçmişte kaydedilmiş **tüm şifreli trafiğin** (ticket'lar üzerinden) çözülebilmesine yol açar — forward secrecy'nin fiilen ortadan kalkması. Ayrıca ticket'ın brute-force'a açık, zayıf bir anahtarla şifrelenip şifrelenmediği de araştırılması gereken bir alandır.

---

## 13. Health Check Mekanizması Üzerinden SSRF

LB'ler, backend sunucuların "sağlıklı" olup olmadığını anlamak için periyodik olarak health check istekleri gönderir. Bu mekanizma genellikle **yapılandırılabilir bir URL** kabul eder:

```yaml
health_check:
  path: /health
  interval: 5s
```

Eğer bu path, yönetim arayüzü üzerinden (yetersiz yetkilendirmeyle) **dışarıdan değiştirilebilir** bir parametreyse, saldırgan LB'nin health check mekanizmasını, kendi kontrolündeki bir SSRF hedefine (iç ağ servisleri, cloud metadata endpoint'leri) yönlendirebilir — LB, kendi network konumundan (genellikle DMZ ile iç ağ arasında ayrıcalıklı bir pozisyonda) bu isteği atacağı için, sonuç doğrudan bir **iç ağ keşif aracına** dönüşür.

---

## 14. Tespit Metodolojisi

1. **Fingerprinting:** HTTP header'ları, cookie isimlendirmeleri ve zamanlama analiziyle (lbd/halberd) LB markasını ve mimarisini belirle.
2. **Protokol farkı testi:** Aynı isteği farklı `Content-Length`/`Transfer-Encoding` kombinasyonlarıyla gönderip yanıt zamanlaması/içeriğindeki tutarsızlıkları (request smuggling göstergesi) ara.
3. **Cookie çözümleme:** Kalıcılık cookie'lerini decode edip iç ağ IP/port bilgisi sızıp sızmadığını kontrol et.
4. **Header güven testi:** `X-Forwarded-For`, `X-Forwarded-Proto`, `Host` header'larını manipüle ederek backend'in bu değerlere ne kadar güvendiğini test et.
5. **Direct-origin erişim testi:** Sızdırılan backend IP'sine doğrudan istek atıp WAF/LB katmanını tamamen atlayıp atlayamadığını doğrula.
6. **Path normalization farkı:** Aynı path traversal/encoding varyasyonlarını hem LB hem backend'e ayrı gönderip auth bypass ara.
7. **Yönetim arayüzü keşfi:** Alternatif portlarda (8443, 9090 vb.) barındırılan yönetim panellerini tara, kimlik doğrulamasız endpoint'leri fuzz et.
8. **Protokole duyarlı fuzzing:** Mümkünse izole bir test ortamında (üreticinin sunduğu deneme sürümü/sanal appliance üzerinde), HTTP/TLS gramerine uygun mutasyonlarla coverage-guided fuzzing çalıştır.

---

## Virtual Patch — Acil Durum Yaması

Bir load balancer'da yukarıdaki türden bir zafiyet **bugün** tespit edilirse, üretici yaması (firmware update) genellikle günler/haftalar sürer. Bu süre zarfında saatler içinde devreye alınabilecek geçici önlemler:

**1. Request Smuggling'e Karşı Acil Normalizasyon**

LB seviyesinde, hem `Content-Length` hem `Transfer-Encoding` içeren istekleri **anında reddetme** kuralı eklenir — bu RFC'ye göre zaten geçersiz bir istektir.

```nginx
# NGINX: çelişkili header kombinasyonunu anında reddet
if ($http_transfer_encoding ~* "chunked" ) {
    if ($http_content_length) {
        return 400;
    }
}
```

**2. Forwarded Header'lara Güveni Acilen Kesme**

Backend'e acil bir doğrulama katmanı eklenir — `X-Forwarded-*` header'ları sadece **gerçekten LB'den geliyorsa** (bilinen LB IP aralığından) kabul edilir, aksi halde temizlenir.

```python
TRUSTED_LB_IPS = {"10.0.0.5", "10.0.0.6"}

def sanitize_forwarded_headers(request):
    if request.remote_addr not in TRUSTED_LB_IPS:
        request.headers.pop("X-Forwarded-For", None)
        request.headers.pop("X-Forwarded-Proto", None)
```

**3. Backend'e Doğrudan Erişimi Acilen Kapatma**

Backend sunucuların güvenlik grubu/firewall kuralı, **sadece LB'nin IP'sinden** gelen bağlantıları kabul edecek şekilde anında daraltılır — WAF bypass senaryosunu (Bölüm 7) mimariyi değiştirmeden kapatır.

```bash
# iptables: sadece LB IP'sinden 443'e izin ver, gerisini reddet
iptables -A INPUT -p tcp --dport 443 -s 10.0.0.5 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP
```

**4. Yönetim Panelini Acilen İzole Etme**

Yönetim arayüzü (Web UI, API), bilinen CVE'ler açıklanana kadar **sadece VPN/bastion üzerinden** erişilebilir hale getirilir, dış dünyaya kapatılır — CVE-2020-5902 ve CVE-2019-19781 gibi açıkların gerçek dünyada bu kadar yıkıcı olmasının nedeni, yönetim panellerinin gereksiz yere internete açık bırakılmasıydı.

```bash
# Yönetim portunu sadece belirli bir bastion IP'sine aç
iptables -A INPUT -p tcp --dport 8443 -s <bastion_ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP
```

**5. Kalıcılık Cookie'sini Acilen Ek Katmanla Sarmalama**

Cookie'nin kendisi değiştirilemiyorsa (üretici implementasyonu), en azından cookie'nin **HttpOnly + Secure** flag'leriyle işaretlenmesi ve mümkünse ek bir reverse-proxy katmanında **yeniden şifrelenerek** dışarıya taşınması sağlanır — sızdırdığı ham iç ağ bilgisini gizler.

```nginx
proxy_cookie_flags BIGipServerPool_HTTP secure httponly;
```

**6. Health Check Endpoint'ini Acilen Sabitleme**

Health check path'i, yönetim arayüzü üzerinden dinamik olarak değiştirilebiliyorsa, bu alan geçici olarak **salt-okunur/sabit** hale getirilir, SSRF'e açık bir keyfi URL girişine izin verilmez.

**Dikkat edilmesi gerekenler:**

* Bu önlemler **geçicidir** — üretici tarafından yayınlanan resmi firmware/yazılım güncellemesi mutlaka en kısa sürede uygulanmalıdır.
* Backend erişimini IP bazlı kısıtlamak, LB'nin kendisi ele geçirilirse (Bölüm 9-10'daki bellek/RCE senaryoları) yeterli olmaz — bu senaryoda LB'nin kendisi izole edilmeli veya devre dışı bırakılmalıdır.
* Yama sonrası mutlaka fingerprinting adımları (Bölüm 2) tekrarlanarak, cihazın artık hangi bilgiyi sızdırdığı yeniden doğrulanmalıdır.

---

## Kalıcı Çözümler

**Protokol Tutarlılığı:** LB ve backend, HTTP header ayrıştırma kurallarında (özellikle CL/TE önceliği) **tam olarak aynı** implementasyonu veya kütüphaneyi kullanmalı; mümkünse LB ile backend arasındaki bağlantılarda HTTP/1.1 keep-alive yerine **her istek için yeni bağlantı** (connection: close) kullanılarak smuggling'in etkisi sınırlandırılmalı.

**Sıfır Güven Mimarisi:** Backend, hiçbir `X-Forwarded-*` header'ına veya "iç ağdan geldiği" varsayımına körü körüne güvenmemeli; her isteğin kimliğini kendi içinde bağımsız olarak doğrulamalı (bkz. Broken Access Control yazımızdaki mikro servis güven ilişkisi bölümü).

**Yönetim Düzlemi İzolasyonu:** Control plane (yönetim arayüzü) ile data plane (trafik işleme) ağ seviyesinde tamamen ayrılmalı; yönetim arayüzüne erişim sadece VPN/bastion + MFA ile sınırlandırılmalı.

**Kriptografi:** TLS session ticket anahtarları düzenli olarak (idealen her birkaç saatte) rotate edilmeli; donanım hızlandırıcı sürücüleri ve TLS kütüphaneleri üretici güvenlik bültenleri takip edilerek güncel tutulmalı.

**İzleme:** LB loglarında CL/TE çelişkisi taşıyan istekler, anormal path traversal desenleri ve health check konfigürasyon değişiklikleri için otomatik alarm kuralları tanımlanmalı.

**Fuzzing ve Envanterleme:** Kritik altyapıdaki LB/API Gateway modelleri (F5, Citrix, Envoy, Kong, HAProxy) düzenli olarak hem üretici yamaları hem de bağımsız güvenlik araştırmaları (CVE veritabanları, konferans yayınları) açısından takip edilmeli.

---

## Yaygın Senaryolar

* CL.TE ile HTTP request smuggling
  `Content-Length: 13` + `Transfer-Encoding: chunked` çelişkisi → sıradaki isteğe kod enjeksiyonu

* F5 BIG-IP kalıcılık cookie'sinden iç ağ IP sızıntısı
  `BIGipServerPool_HTTP=1677787402.20480.0000` → little-endian decode → backend IP:port

* Forwarded header manipülasyonu ile IP whitelist atlatma
  `X-Forwarded-For: 127.0.0.1`

* Path normalization farkıyla auth bypass
  `GET /tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp`

* Sızdırılan backend IP'sine doğrudan erişimle WAF bypass
  `curl -H "Host: target.com" https://<backend_ip>/admin`

* iRules/Tcl enjeksiyonu ile trafik motorunda kod çalıştırma
  `eval [HTTP::header "X-Custom-Data"]`

* Health check mekanizması üzerinden SSRF
  `health_check.path` → iç ağ/metadata endpoint'ine yönlendirme

* Integer overflow ile bellek yolsuzluğu tetikleme
  `Content-Length: 4294967296` → 32-bit taşma → küçük buffer ayrımı

---
