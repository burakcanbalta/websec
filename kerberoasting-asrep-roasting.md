![Kerberos 3-Way Handshake](kerberos-flow.svg)

**Kerberoasting** ve **AS-REP Roasting**, Active Directory ortamlarındaki en yaygın ve en yüksek etkili yatay/dikey hareket teknikleridir — ikisi de exploit değil, **protokolün kendi tasarımının** istismarıdır. Kerberos hiçbir zaman "kırık" değildir; sömürülen şey, protokolün gerektirdiği bir davranışın (servis hesabı şifresiyle şifrelenmiş bir bilet üretmek) **zayıf insan şifreleriyle** birleştiğinde ortaya çıkan matematiksel gerçektir. Bu yüzden bu iki teknik, AD güvenliğinde hem en sık karşılaşılan hem de en yanlış anlaşılan konulardan biridir.

Bu yazı, Kerberos'un üç aktörünü (KDC, AS, TGS) ve bilet mekanizmasını sıfırdan anlatarak başlıyor, AS-REP Roasting ve Kerberoasting'in tam mekanizmasını adım adım işliyor, ardından OpSec seviyesinde tespit atlatma, honeytoken analizi, delegasyon zincirleri, şifresiz (passwordless) AD ortamlarındaki saldırı yüzeyine ve protokol seviyesinde kendi araç geliştirme konusuna kadar ilerliyor. Sonunda hangi Event ID'lerin izlenmesi gerektiğini gösteren bir tespit rehberiyle kapanıyor.

---

## 1. Temel Seviye: Kerberos Protokolü ve Mimarisi

### 1.1 Üç Aktör

Kerberos, "bileti taşıyan kişiye güven" mantığıyla çalışan bir kimlik doğrulama protokolüdür (bkz. OAuth/OIDC yazımızdaki Bearer Token felsefesiyle kavramsal benzerlik — ama Kerberos çok daha eski ve simetrik kriptografiye dayanır).

| Aktör | Rol |
|---|---|
| **KDC** (Key Distribution Center) | Domain Controller üzerinde çalışan, tüm bilet üretiminden sorumlu merkezi servis |
| **AS** (Authentication Service) | KDC'nin, kullanıcının kimliğini doğrulayıp ilk bileti (TGT) verdiği alt bileşeni |
| **TGS** (Ticket Granting Service) | KDC'nin, TGT karşılığında belirli bir servise özel bilet (TGS bileti) ürettiği alt bileşeni |

AS ve TGS, aynı fiziksel sunucuda (Domain Controller) çalışır — kavramsal olarak ayrılırlar ama ikisi de KDC'nin bir parçasıdır.

### 1.2 Kerberos 3-Way Handshake — Adım Adım

Yukarıdaki diyagramdaki akışı sözel olarak takip edelim:

**1. AS-REQ:** İstemci, kullanıcı adını ve (preauth açıksa) şu anki zaman damgasını **kullanıcının NT hash'i ile şifreleyerek** KDC'ye gönderir. Bu adım "ben gerçekten bu kullanıcıyım, çünkü doğru şifreyle şifreledim" demenin bir yoludur — şifrenin kendisi asla ağda düz metin olarak dolaşmaz.

**2. AS-REP:** KDC, kullanıcı veritabanındaki (Active Directory) hash ile şifreyi çözmeyi dener. Başarılıysa, istemciye iki şey döner: bir **TGT (Ticket Granting Ticket)** ve bir **oturum anahtarı (session key)**. TGT'nin kendisi **KDC'nin kendi hesabının** (`krbtgt`) hash'iyle şifrelenmiştir — istemci bunu çözemez, sadece taşır. Oturum anahtarı ise kullanıcının hash'iyle şifrelenmiş olarak gelir; istemci bunu çözüp sonraki adımlarda kullanır.

> **Kritik nokta:** Eğer preauth (ön kimlik doğrulama) kapalıysa, KDC adım 1'de hiçbir doğrulama yapmadan doğrudan AS-REP döner — ve bu yanıtın bir kısmı kullanıcının hash'iyle şifrelenmiştir. Bu, **AS-REP Roasting**'in tam kalbidir (Bölüm 2).

**3. TGS-REQ:** İstemci, belirli bir servise (örneğin bir SQL Server'a) erişmek istediğinde, elindeki TGT'yi ve hedef servisin **SPN**'ini KDC'nin TGS bileşenine gönderir.

**4. TGS-REP:** KDC, TGT'nin geçerliliğini (kendi `krbtgt` hash'iyle) doğrular ve **hedef servis hesabının şifre hash'i ile şifrelenmiş** bir TGS bileti üretir. Bu bilet, istemcinin o servise erişim yetkisi olup olmadığına bakılmaksızın üretilir — KDC sadece "bu TGT geçerli mi" diye kontrol eder, yetkilendirme kararı **servisin kendisine** bırakılmıştır.

> **Kritik nokta:** Bu adımda üretilen bilet, **servis hesabının şifresiyle şifrelidir** ve istemci bu bileti normal bir işlem olarak alır. Bu, **Kerberoasting**'in tam kalbidir (Bölüm 3).

**5. AP-REQ:** İstemci, TGS biletini doğrudan hedef servise sunar.

**6. AP-REP (opsiyonel):** Servis, karşılıklı kimlik doğrulama (mutual authentication) istiyorsa bir yanıt döner.

### 1.3 TGT vs TGS Bileti

| | TGT | TGS Bileti |
|---|---|---|
| Kim üretir | AS | TGS |
| Neyle şifrelenir | `krbtgt` hesabının hash'i | Hedef servis hesabının hash'i |
| Ne için kullanılır | Yeni TGS bileti istemek | Belirli bir servise erişmek |
| Kim çözebilir | Sadece KDC | Sadece o servis hesabı |

### 1.4 SPN (Service Principal Name)

Bir servis hesabının AD içinde **benzersiz şekilde tanımlanmasını** sağlayan yapıdır — `MSSQLSvc/sql01.corp.local:1433` gibi bir format alır. `setspn -Q */*` komutuyla domaindeki tüm SPN'ler listelenebilir. SPN'e sahip her hesap, potansiyel bir Kerberoasting hedefidir — çünkü **herhangi bir domain kullanıcısı**, o SPN için TGS bileti isteyebilir.

---

## 2. AS-REP Roasting

### 2.1 Saldırı Mekanizması

AS-REP Roasting, bir kullanıcı hesabında **"Do not require Kerberos preauthentication"** ayarının açık olmasını istismar eder (`userAccountControl` özniteliğindeki `DONT_REQ_PREAUTH` bayrağı). Bu ayar açıksa, saldırgan **hiçbir şifre bilmeden** doğrudan bir AS-REQ isteği gönderebilir — KDC, kullanıcının kimliğini doğrulamadan direkt AS-REP döner, ve bu yanıtın bir bölümü **kullanıcının NT hash'i ile şifrelenmiştir.**

```
[Saldırgan] --AS-REQ (preauth yok)--> [KDC]
[KDC] --AS-REP (kullanıcı hash'iyle şifreli veri)--> [Saldırgan]
```

Saldırgan bu yanıtı offline olarak, herhangi bir ağ trafiği üretmeden kırmaya çalışır.

### 2.2 Keşif (Enumeration)

```bash
# Impacket ile preauth kapalı kullanıcıları tara
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.5
```

```powershell
# PowerView ile aynı hesapları LDAP üzerinden tespit et
Get-DomainUser -PreauthNotRequired -Properties samaccountname
```

### 2.3 Hash Çıkarma ve Kırma

```bash
GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.10.10.5
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

`-m 18200`, Hashcat'e bu hash'in bir **Kerberos AS-REP** hash'i olduğunu belirtir.

---

## 3. Kerberoasting

### 3.1 Saldırı Mekanizması

Kerberoasting, AD ortamındaki **servis hesaplarının** (bir kullanıcının bir servisi çalıştırmak için kullandığı hesap) zayıf şifrelerini hedef alır. Bir bilgisayar hesabının şifresi 120 karakter civarında rastgele üretildiği için pratikte kırılamaz — ama insan tarafından belirlenen servis hesabı şifreleri genellikle çok daha zayıftır.

**Kritik gerçek:** Herhangi bir domain kullanıcısı, SPN'e sahip bir servis için TGS bileti talep edebilir — **hiçbir özel yetkiye gerek yoktur.** KDC, bu bileti isteyen kullanıcının o servise gerçekten erişim yetkisi olup olmadığını **kontrol etmez**; yetkilendirme kararını servisin kendisine bırakır ve isteneni üretir. Bilet, servis hesabının şifre hash'iyle şifrelenmiş olarak döner — saldırgan bu bileti hafızadan çekip offline kırar.

### 3.2 Keşif ve Bilet İsteme

```bash
# Impacket
GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.5 -request
```

```powershell
# Rubeus ile tüm SPN'lere kerberoast isteği
Rubeus.exe kerberoast /outfile:hashes.txt
```

```powershell
# Mimikatz ile mevcut oturumdaki biletleri listeleme
mimikatz # kerberos::list /export
```

### 3.3 Hash Kırma

```bash
hashcat -m 13100 hashes.txt rockyou.txt
```

`-m 13100`, Kerberos 5 TGS-REP (RC4 şifreleme, etype 23) hash formatını belirtir.

---

## 4. İleri Seviye: Savunma Atlatma ve OpSec

### 4.1 Şifreleme Türü Downgrade (RC4 vs AES)

RC4 (arcfour, etype 23) hash'leri, AES-256 (etype 18) hash'lerine göre **çok daha hızlı kırılır** — çünkü RC4, daha zayıf bir anahtar türetme fonksiyonu kullanır. Eski araçlar, TGS-REQ isteğinde desteklenen şifreleme türlerini manipüle ederek KDC'yi RC4 kullanmaya **zorlamaya** çalışırdı (`-etype`/`downgrade` bayrakları). Ancak modern SIEM/EDR sistemleri artık bu downgrade davranışının kendisini bir anomali olarak işaretliyor.

**İleri seviye yaklaşım:** RC4'e zorlamak yerine, AES-256 hash'lerini **olduğu gibi** tespit edilmeden çekip, kırma işlemini yerel makinede değil **GPU cluster'ları veya bulut altyapıları (AWS/Azure spot instance'ları)** üzerinde gerçekleştirmek — saldırı yüzeyini "ağ isteği" katmanından "offline hesaplama" katmanına taşımak, tespit riskini büyük ölçüde azaltır.

### 4.2 Jitter ve Zamana Yayma

Klasik araçlar (temel `GetUserSPNs.py`, `Rubeus.exe`) saniyeler içinde onlarca-yüzlerce TGS isteği gönderir — bu, **Event ID 4769**'da ani bir hacim artışı olarak SIEM kurallarını anında tetikler. OpSec-safe bir yaklaşım, istekleri normal kullanıcı davranışını taklit edecek şekilde **rastgele aralıklarla** (jitter), örneğin 10 dakikada bir, gönderen özel scriptlerle yapılır.

### 4.3 Hedefli (Targeted) Kerberoasting

Domaindeki **tüm** SPN'leri çekmek yerine, sadece **zayıf şifre politikasına sahip olduğu bilinen** veya kritik haklara (Domain Admin, Local Admin) dolaylı erişimi olan **tek bir spesifik hesabı** hedeflemek, hem gürültüyü azaltır hem de başarı olasılığını artırır — bu, IDOR yazımızdaki "geniş tarama yerine hedefli test" prensibinin AD dünyasındaki karşılığıdır.

```powershell
# Tek bir SPN'e hedefli istek
Rubeus.exe kerberoast /user:svc-sql /outfile:targeted.txt
```

### 4.4 Bellekten Okuma vs. Ağ İzleme

`Rubeus` gibi araçlar biletleri doğrudan **LSASS (Local Security Authority Subsystem Service)** prosesinin bellek önbelleğinden çeker — bu, ağ trafiği üretmez ama LSASS'a erişim genellikle EDR tarafından yoğun izlenir (bkz. Windows/AD serimizdeki credential dumping konuları). Alternatif olarak, ağ trafiğini pasif dinleyerek (network sniffing) biletleri yakalamak, bellek erişimi izini bırakmaz ama fiziksel/ağ konumlandırması gerektirir — iki yöntemin de kendine özgü OpSec maliyeti vardır.

### 4.5 Honeytoken (Bal Küpü) Tespiti

Savunma ekipleri, AD ortamına **hiçbir gerçek işlevi olmayan sahte SPN'li hesaplar** yerleştirir — bu hesapların bileti istendiği an (Kerberoasting'in kendisi tetiklendiği an) SOC'a yüksek öncelikli bir alarm gider. İleri seviye bir saldırganın bu tuzakları ayırt etmesi gerekir:

* **Öznitelik analizi:** Gerçek hesapların `pwdLastSet`, `lastLogonTimestamp`, `badPwdCount` gibi değerleri **hareketlidir** ve genellikle bir gruba üyedirler; honeytoken hesaplar çoğunlukla statik ve izole kalır.
* **Ağ trafiği/canlılık kontrolü:** Hedef servisin IP'sine gerçekten trafik gidip gitmediğini veya ilgili portun (MSSQL için 1433 gibi) gerçekten açık olup olmadığını kontrol etmeden bilet istememek — bir SPN'in arkasında **hiçbir çalışan servis yoksa**, bu güçlü bir honeytoken sinyalidir.

---

## 5. Protokol Sınırlarını Zorlayan Zincirleme Saldırılar

### 5.1 S4U2self / RBCD Zinciri

Kaynak Tabanlı Kısıtlı Delegasyon (**RBCD — Resource-Based Constrained Delegation**) yapılandırmalarında, `S4U2self` uzantısı bir bilgisayar hesabının **kendi adına** başka bir kullanıcı için bilet talep etmesine izin verir. Bu mekanizma manipüle edilerek sahte biletler üretilebilir ve bu, klasik Kerberoasting akışıyla zincirlenebilir — örneğin RBCD ile elde edilen bir bilgisayar hesabı context'i, o hesabın erişebildiği SPN'lere karşı ek bir Kerberoasting yüzeyi açar.

### 5.2 Shadow Credentials (Kimlik Bilgisi Gerektirmeyen Yol)

Hedef servis hesabının şifresini kırmaya çalışmak yerine, hesabın `msDS-KeyCredentialLink` özniteliğine **kendi ürettiğimiz bir public key'i haritalayarak**, şifreye hiç ihtiyaç duymadan doğrudan PKINIT üzerinden TGT/TGS bileti üretmek mümkündür (bu yeterli yazma yetkisi gerektirir — örneğin `GenericWrite` gibi bir ACL zafiyeti üzerinden elde edilmiş olabilir). Bu teknik, "hash kırmayı" tamamen atlayarak doğrudan kimlik doğrulama sürecine sahte bir kriptografik materyal enjekte eder.

### 5.3 Golden Ticket Üzerinden Kerberoasting

`krbtgt` hesabının hash'i ele geçirilmişse (Golden Ticket senaryosu), saldırgan artık gerçek AS-REQ/AS-REP akışına hiç ihtiyaç duymadan **kendi sahte TGT'lerini** üretebilir — bu TGT'lerle istenen herhangi bir SPN için TGS bileti talep edilebilir, ve bu bilet yine hedef servis hesabının hash'iyle şifrelenmiş olarak döner. Bu, Kerberoasting'in **Golden Ticket persistence'ı ile birleştirildiği**, tespit edilmesi son derece zor bir zincirleme senaryodur.

---

## 6. Şifresiz (Passwordless) AD Ortamlarında Saldırı Yüzeyi

Modern AD ortamları Windows Hello for Business (WHfB) veya Akıllı Kart entegrasyonuyla şifresiz kimlik doğrulamaya geçiyor — bu, klasik şifre kırma işlevini büyük ölçüde geçersiz kılar, ama saldırı yüzeyini **yok etmez, taşır.**

### 6.1 Certificate-Based Kerberos (PKINIT)

AS-REQ/AS-REP süreçleri X.509 sertifikalarıyla yapıldığında, saldırı yüzeyi artık şifre hash'i değil **sertifika altyapısının kendisidir.** Active Directory Certificate Services (AD CS) üzerindeki bilinen zafiyet ailesi (**ESC1'den ESC13'e**) — yanlış yapılandırılmış sertifika şablonları, zayıf isim eşleme mantığı, denetlenmemiş kayıt yetkileri gibi — Kerberos bilet süreçlerinin dolaylı olarak ele geçirilmesine yol açabilir. Bu konu tek başına ayrı ve derin bir araştırma alanıdır.

### 6.2 NTLM Fallback / Downgrade

Sistemleri Kerberos korumasından çıkarıp eski nesil NTLM protokolüne **geri düşürmeye zorlamak**, hash yakalama tekniklerini (Responder, NTLM relay) yeniden mümkün kılar — passwordless bir ortamda bile, NTLM fallback yanlış yapılandırılmışsa eski nesil saldırı yüzeyi hâlâ açık kalabilir.

---

## 7. Sıfırdan Kendi Kerberos Araçlarını Yazmak

Hazır araçlar (Impacket, Mimikatz, Rubeus) genellikle imzalandığı, hash'lendiği veya davranışsal analizle profillendiği için, gerçek bir araştırma/0-day seviyesinde **kendi araçlarını yazmak** gerekir.

### 7.1 Raw ASN.1 / DER Manipülasyonu

Kerberos paketleri **ASN.1** formatında kodlanır. Python'da `scapy` benzeri kütüphaneler veya C# ile ham ağ paketleri oluşturarak, işletim sisteminin kendi Kerberos API'lerini (Windows'ta **SSPI**) tamamen atlayıp doğrudan KDC'nin dinlediği **88. port** ile konuşan özel araçlar geliştirmek, hem tespit imzalarını (araç bazlı EDR imzaları genellikle bilinen API çağrı zincirlerini izler) atlatır hem de protokolün **RFC 4120**'de tanımlanan tüm esnekliğinden faydalanmayı mümkün kılar.

```python
# Kavramsal iskelet: ham AS-REQ paketi oluşturma mantığı
from pyasn1.codec.der import encoder
from pyasn1.type import univ, namedtype

# KRB-AS-REQ ASN.1 yapısı elle inşa edilir,
# preauth alanları bilinçli olarak boş bırakılabilir (AS-REP Roasting testi için)
as_req = build_as_req(client_principal, realm, sname)
raw_packet = encoder.encode(as_req)
send_to_kdc(raw_packet, kdc_ip, port=88)
```

### 7.2 Hafıza Manipülasyonu (LSASS Bypass)

Biletleri Windows API'leri üzerinden istemek yerine, doğrudan **LSASS** prosesinin belleğindeki bilet önbelleği (ticket cache) veri yapılarını manuel olarak ayrıştırıp (parsing) belleğe enjekte etmek veya çalmak, `Rubeus`/`Mimikatz` gibi araçların bıraktığı **API çağrı imzalarını** (örneğin `LsaCallAuthenticationPackage` çağrıları) tamamen atlar — bu, imza tabanlı EDR tespitine karşı en dirençli yaklaşımlardan biridir, ama LSASS bellek erişiminin kendisi zaten yüksek riskli bir davranış olarak izlendiği için ayrı bir OpSec katmanı (process injection, handle manipülasyonu) gerektirir.

---

## 8. Tespit — Hangi Event ID'ler İzlenmeli?

| Event ID | Anlamı | Neden Önemli |
|---|---|---|
| **4768** | TGT talebi (AS-REQ/AS-REP) | Preauth kapalı hesaplarda anormal sıklıkta 4768 → AS-REP Roasting belirtisi |
| **4769** | TGS bileti talebi | Kısa sürede çok sayıda farklı SPN için 4769 → klasik Kerberoasting imzası |
| **4771** | Kerberos preauth başarısız | Ardışık başarısız preauth denemeleri → brute-force/tarama göstergesi |
| **4776** | NTLM kimlik doğrulama denemesi | Kerberos'tan NTLM'e beklenmedik düşüş (downgrade) izleme |
| **4741 / 4742** | Bilgisayar/kullanıcı hesabı özellik değişikliği | `msDS-KeyCredentialLink` değişikliği → Shadow Credentials göstergesi |
| **5136** | Dizin hizmeti nesne değişikliği | RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) değişikliklerini yakalamak için |

**Pratik tespit kuralı örneği (kavramsal):** Aynı kaynak IP/kullanıcıdan, kısa bir zaman penceresinde (örneğin 5 dakika) **farklı SPN'lere yönelik** birden fazla 4769 event'i geliyorsa ve şifreleme türü alanı `0x17` (RC4) ise, bu yüksek olasılıkla bir Kerberoasting taramasıdır — özellikle bu SPN'lerin normalde o kullanıcı tarafından hiç erişilmeyen servisler olması durumunda.

---

## Savunma — Kalıcı Çözümler

**Şifre Hijyeni:** Servis hesaplarının şifreleri **en az 25+ karakter, rastgele üretilmiş** olmalı — pratikte bu, çoğu offline kırma saldırısını anlamsız hale getirir.

**gMSA Kullanımı:** Mümkün olan her yerde klasik servis hesapları yerine **gMSA (group Managed Service Account)** kullanılmalı — şifre otomatik ve periyodik olarak rotate edilir, insan tarafından bilinmez/yönetilmez.

**Preauth Zorunluluğu:** `DONT_REQ_PREAUTH` bayrağı olan hesaplar düzenli olarak taranmalı ve gerekmedikçe bu ayar kapatılmalı.

**Şifreleme Türü Zorlaması:** Mümkünse ortamda yalnızca **AES** (RC4 devre dışı) desteklenmeli — bu, hem downgrade saldırılarını hem de klasik hashcat mod 13100 akışını zorlaştırır (AES hash'leri RC4'e göre çok daha yavaş kırılır).

**Honeytoken Dağıtımı:** Gerçekçi görünen (ama gerçek trafiği olmayan) sahte SPN'li hesaplar dağıtılmalı, bu hesaplara yönelik 4769 event'leri **en yüksek öncelikli** alarm olarak yapılandırılmalı.

**Delegasyon Denetimi:** Unconstrained delegation mümkün olduğunca kaldırılmalı; RBCD ve `msDS-KeyCredentialLink` değişiklikleri (Event ID 5136, 4742) düzenli denetlenmeli.

**Davranışsal İzleme:** Tek kaynaktan kısa sürede çok sayıda farklı SPN'e 4769 isteği, RC4 şifreleme türü kullanımı ve mesai saatleri dışı toplu bilet talepleri için otomatik korelasyon kuralları (SIEM) tanımlanmalı.

---

## Yaygın Senaryolar

* AS-REP Roasting ile şifresiz hash çekme
  `GetNPUsers.py corp.local/ -usersfile users.txt -no-pass` → preauth kapalı hesap hash'i

* Klasik Kerberoasting
  `GetUserSPNs.py corp.local/user:pass -request` → SPN'li hesabın TGS hash'i

* RC4 downgrade ile hızlı kırma
  Etype 23 (RC4) hash'i hashcat mod 13100 ile saatler yerine dakikalar içinde kırma

* Hedefli, düşük gürültülü Kerberoasting
  Tek bir zayıf-şifreli servis hesabına, jitter'lı isteklerle OpSec-safe saldırı

* Shadow Credentials ile şifresiz bilet üretimi
  `msDS-KeyCredentialLink` üzerinden sahte public key haritalama → PKINIT ile doğrudan TGT

* Golden Ticket + Kerberoasting zinciri
  `krbtgt` hash'i ile sahte TGT üretimi → herhangi bir SPN için TGS bileti talep etme

* RBCD ile yetki zinciri
  `msDS-AllowedToActOnBehalfOfOtherIdentity` manipülasyonu → S4U2self/S4U2proxy zinciriyle bilet üretimi

---
