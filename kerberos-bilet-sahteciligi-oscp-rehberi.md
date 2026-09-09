# Kerberos Bilet Sahteciliği: Golden Ticket'tan Diamond Ticket'a Kapsamlı Bir Kırmızı Takım Rehberi

> **Not:** Bu yazıdaki teknikler yalnızca yetkilendirilmiş penetrasyon testleri, CTF ortamları, kendi laboratuvarınız veya OSCP/CRTP gibi sertifika hazırlıkları için düşünülmüştür. Aşağıda anlatılan işlemleri yazılı izniniz olmayan hiçbir sistemde uygulamayın; yetkisiz erişim birçok ülkede suç teşkil eder.

Active Directory ortamlarına sızan hemen her kırmızı takım operasyonunda er ya da geç aynı soruyla karşılaşırsınız: "Domain Admin yetkisini bir kez ele geçirdim, peki bunu nasıl kalıcı hale getiririm — hem de fark edilmeden?" Cevap neredeyse her zaman Kerberos protokolünün güven zincirinde saklıdır. Bu yazıda, konuyu sıfırdan başlatıp OSCP seviyesinin bir hayli ötesine, güncel CVE'lere ve threat hunting pratiklerine kadar götürüyoruz.

---

## 0. Terimler Sözlüğü (Hızlı Referans)

Yeni başlayanlar için, makale boyunca sık geçecek terimleri tek yerde topladık — video çekerken ekrana sabitlenmiş bir "cheat sheet" olarak da kullanılabilir.

| Terim | Açılımı | Kısaca Ne İşe Yarar |
|---|---|---|
| **AD** | Active Directory | Microsoft'un dizin/kimlik yönetim servisi |
| **DC** | Domain Controller | AD veritabanını barındıran ve kimlik doğrulayan sunucu |
| **KDC** | Key Distribution Center | DC üzerinde çalışan, Kerberos biletlerini üreten servis |
| **KRBTGT** | Kerberos Ticket Granting Ticket (hesap adı) | Tüm TGT'leri imzalayan özel domain hesabı |
| **TGT** | Ticket Granting Ticket | "Kimlik doğrulandı" belgesi; diğer biletleri almak için kullanılır |
| **TGS** | Ticket Granting Service (bileti) | Belirli bir servise erişim için alınan bilet |
| **AS-REQ / AS-REP** | Authentication Service Request/Reply | TGT almak için KDC ile yapılan ilk el sıkışma |
| **TGS-REQ / TGS-REP** | TGS talebi/cevabı | TGT ile belirli bir servis için bilet isteme aşaması |
| **PAC** | Privilege Attribute Certificate | Biletin içindeki, kullanıcının grup üyeliklerini taşıyan yetki verisi |
| **SPN** | Service Principal Name | Bir servisin Kerberos'a kayıtlı benzersiz adı |
| **SID** | Security Identifier | Kullanıcı/grup/bilgisayar için benzersiz güvenlik kimliği |
| **etype** | Encryption Type | Biletin şifrelendiği algoritma (örn. etype 23 = RC4, etype 18 = AES-256) |
| **PKINIT** | Public Key Cryptography for Initial Authentication | Sertifika/akıllı kart ile Kerberos kimlik doğrulama uzantısı |
| **AD CS** | Active Directory Certificate Services | Kurumsal sertifika (PKI) altyapısı |
| **PtT** | Pass-the-Ticket | Ele geçirilen/üretilen bir Kerberos biletini başka bir oturuma enjekte etme |

---

## 1. Temel Seviye: Kerberos'un Güven Modelini Anlamak

Bilet sahteciliği yapmadan önce neyi sahteleyeceğinizi bilmeniz gerekir. Kerberos'ta güven, üç anahtar bileşen üzerine kuruludur.

### 1.1 KRBTGT Hesabı

Her domain'de otomatik oluşturulan, devre dışı bırakılamayan bu özel hesap, Domain Controller üzerindeki Key Distribution Center'ın (KDC) kalbidir. KRBTGT hesabının şifre hash'i:

- Domain'deki **tüm TGT (Ticket Granting Ticket)** biletlerini şifrelemek,
- Bu biletlerin bütünlüğünü imzalamak

için kullanılır. Bu hash'i ele geçiren kişi, pratikte KDC'nin kendisi kadar güç kazanır.

### 1.2 Bilgisayar (Makine) Hesapları

AD'deki her bilgisayar nesnesinin (örn. `DC01$`) rastgele üretilmiş, 120 karakterlik bir şifresi vardır. Bu şifre, o makine üzerinde çalışan servisler için üretilen **TGS (Ticket Granting Service)** biletlerini şifrelemekte kullanılır. Bir SQL sunucusunun makine hesabı hash'ini ele geçirmek, o sunucunun servislerine sahte bilet üretme kapısını açar.

### 1.3 PAC (Privilege Attribute Certificate)

Kerberos biletinin içine gömülü olan PAC, kullanıcının hangi güvenlik gruplarına (Domain Admins, Enterprise Admins, RID 512 vb.) üye olduğunu taşıyan veridir. Windows, yetkilendirme kararlarını büyük ölçüde bu alana bakarak verir — PAC'i manipüle edebilen biri, yetkilendirmeyi manipüle edebilir demektir. PAC, KDC tarafından imzalanır; bu imza olmadan sistem PAC içeriğine güvenmez.

Bu üç kavramı iyi kavradıktan sonra, saldırı tekniklerinin hepsi aslında "bu imzayı kim, nasıl ve hangi veriyle atıyor" sorusunun farklı cevaplarından ibarettir.

---

## 2. Orta Seviye: Klasik Bilet Sahteciliği

Bu bölümde Mimikatz ve Rubeus gibi araçlarla biletlerin manuel olarak nasıl üretildiğini (forge edildiğini) inceliyoruz.

### 2.1 Golden Ticket (Altın Bilet)

**Mantık:** KRBTGT hesabının NTLM veya AES-256 hash'i ele geçirildiğinde, saldırgan artık KDC'ye hiç uğramadan kendi makinesinde tamamen sahte bir TGT üretebilir. Bu sahte biletin PAC alanına istediği kullanıcıyı (örneğin kendisini) Domain Admin olarak yazar.

Tipik özellikleri:
- Genellikle varsayılan olarak **10 yıl** geçerlilik süresiyle üretilir.
- KDC ile hiçbir zaman iletişime geçilmediği için, klasik haliyle DC'nin kimlik doğrulama loglarında (Event ID 4768) karşılık gelen bir kayıt oluşmaz — bu da onu hem güçlü hem de (dikkatli SOC ekipleri için) tuhaf kılar.

Araç düzeyinde bu işlem `Mimikatz`'ın `kerberos::golden` modülü veya `Rubeus`'un `golden` komutuyla gerçekleştirilir; üretilen bilet ardından `/ptt` (Pass-the-Ticket) parametresiyle doğrudan bellekteki oturuma enjekte edilir.

### 2.2 Silver Ticket (Gümüş Bilet)

**Mantık:** Bu kez saldırgan KRBTGT hash'ine değil, hedef bir servis hesabının (örn. bir MSSQL sunucusunun veya DC'nin CIFS servisinin) şifre hash'ine sahiptir. TGT'ye ya da KDC'ye hiç ihtiyaç duymadan, doğrudan o **spesifik servis** için sahte bir TGS bileti üretilir.

**Avantajı:** KDC ile hiçbir iletişim kurulmadığından, DC üzerindeki kimlik doğrulama loglarında iz bırakmaz — yalnızca hedef servisin kendi güvenlik günlüğünde bir doğrulama işlemi görünebilir. Bu da Silver Ticket'ı Golden Ticket'a göre çok daha sessiz, ama etki alanı çok daha dar bir teknik yapar.

---

## 3. İleri Seviye: Tespit Atlatma ve Diamond Ticket

Modern SIEM/EDR çözümleri artık klasik Golden Ticket'ları oldukça kolay yakalayabiliyor. Sebebi basit: sıfırdan üretilen bir bilette bilet seri numarası şeması gerçek KDC çıktısıyla uyuşmaz, üstelik KDC loglarında karşılık gelen bir bilet talebi hiç görünmez. Bu boşluğu kapatmak için teknikler evrildi.

### 3.1 Diamond Ticket (Elmas Bilet)

**Mantık:** Sıfırdan sahte bir TGT üretmek yerine, saldırgan önce KDC'den **gerçek, meşru** bir TGT talep eder. Ardından elindeki KRBTGT hash'ini kullanarak bu meşru biletin şifresini çözer, içindeki PAC bölümüne istediği yetkiyi (örn. Domain Admin SID'i) enjekte eder ve bileti yeniden aynı KRBTGT hash'iyle imzalayıp mühürler.

**Neden yakalanması zor?** Çünkü bilet gerçekten KDC tarafından üretilmiştir:
- Seri numarası şeması meşrudur,
- Zaman damgaları tutarlıdır,
- Event ID 4768 kaydı **gerçekten** oluşur, çünkü bilet talebi de gerçektir.

Farklı olan tek şey, biletin içindeki yetki verisidir — ve bu da klasik imza/zaman anomalisi tabanlı tespit kurallarını büyük ölçüde etkisiz bırakır.

### 3.2 Sapphire Ticket (Safir Bilet)

Diamond Ticket fikrini bir adım öteye taşıyan bu yöntem, sahte yetkiyi doğrudan eklemek yerine **meşru bir kullanıcının PAC verisini taklit ederek (impersonation)** biletin içindeki izin izlerini olabildiğince gizler. Amaç aynı: gerçek bir bileti, gerçek bir kimlik doğrulama akışının içinde manipüle etmek.

### 3.3 Şifreleme Türü Seçimi: Neden AES-256?

EDR/SIEM sistemleri, RC4 (HMAC-MD5 tabanlı, etype 23) ile üretilmiş biletleri çok daha kolay ayıklar; çünkü modern, güncellenmiş bir ortamda meşru trafik ağırlıklı olarak AES kullanır ve RC4 biletleri istatistiksel olarak dikkat çeker. Bu yüzden ileri seviye operasyonlarda tüm bilet sahteciliği işlemleri KRBTGT hesabının **AES-256 (etype 18)** anahtarıyla yürütülmelidir.

### 3.4 Hızlı Karşılaştırma Tablosu

Videoda ekrana sabitlenebilecek, dört tekniği bir bakışta özetleyen tablo:

| Özellik | Golden Ticket | Silver Ticket | Diamond Ticket | Sapphire Ticket |
|---|---|---|---|---|
| **Gereken hash** | KRBTGT | Hedef servis hesabı | KRBTGT | KRBTGT |
| **KDC ile iletişim** | Yok | Yok | Var (gerçek TGT istenir) | Var (gerçek TGT istenir) |
| **Kapsam** | Tüm domain | Tek servis | Tüm domain | Tüm domain |
| **Event ID 4768 oluşur mu?** | Hayır (klasik haliyle) | Zaten TGT içermez | Evet, gerçek görünür | Evet, gerçek görünür |
| **Tespit zorluğu** | Orta (seri no/süre anomalisi) | Düşük görünürlük ama dar kapsam | Yüksek (meşru bilet üzerine kurulu) | En yüksek (PAC izleri de gizlenir) |
| **Tipik geçerlilik süresi** | Genelde 10 yıl (özelleştirilebilir) | Sınırsız/özelleştirilebilir | Orijinal TGT süresiyle aynı | Orijinal TGT süresiyle aynı |
| **MITRE ATT&CK ID** | T1558.001 | T1558.002 | T1558.001 (alt teknik) | T1558.001 (alt teknik) |

---

## 4. Uzman Seviyesi: Protokol Araştırması ve Güncel CVE'ler

Bu seviye, Microsoft'un yayınladığı Kerberos güvenlik yamalarını aşmayı ve protokolün tasarım sınırlarını araştırmayı kapsar.

### 4.1 SamAccountName Spoofing Zinciri (CVE-2021-42278 & CVE-2021-42287)

Domain Controller'ların bilgisayar hesabı isimlerini doğrulama mantığındaki bir zafiyet zinciri, sıradan bir kullanıcının kontrol ettiği bir makine hesabı üzerinden, normalde yalnızca yüksek ayrıcalıklı hesaplara ait olması gereken bir kimliğe bürünmesine olanak tanımıştı. Bu zincir, sızma testi camiasında domain'e "sıfırdan Domain Admin'e saniyeler içinde" ulaşan en bilinen örneklerden biri olarak literatüre geçti; Microsoft bu açığı 2021 Kasım yamalarıyla kapattı.

### 4.2 PAC Doğrulama Güncellemeleri (CVE-2022-37967 ve İlgili PAC İmzalama Değişiklikleri)

Microsoft, sahte PAC eklemelerini zorlaştırmak amacıyla Kerberos biletlerine ek imzalama katmanları (PAC_REQUESTOR, PAC_ATTRIBUTES gibi yapılar) ekledi. Güvenlik araştırmacıları için bu, önceki nesil Diamond/Sapphire Ticket tekniklerinin bazı varyantlarını daha maliyetli hale getirdi ve alanı "yeni imzalama şemasının zayıf noktalarını bulma" araştırmasına yöneltti. Bu konudaki güncel gelişmeleri takip etmek için Microsoft'un MSRC danışma sayfalarını ve SpecterOps, Semperis gibi kurumların yayınladığı teknik analizleri düzenli izlemenizi öneririm.

### 4.3 Cross-Forest Golden Ticket (SID History Enjeksiyonu)

Bir alt (child) domain ele geçirildiğinde, o domain'in KRBTGT hash'i ve SID History özniteliği manipülasyonu birlikte kullanılarak, ormanın (forest) kök domain'inde Enterprise Admins yetkisine sahip bir kimliğe bürünülebilir. Bu teknik, forest'lar arası güven ilişkisinin doğası gereği "bir alt domain, kök domain kadar güvenli değildir" ilkesinin somut bir yansımasıdır ve büyük kurumsal ortamlarda segmentasyon tasarımının neden kritik olduğunu gösterir.

### 4.4 RODC (Read-Only Domain Controller) Sınırlamaları

RODC'lerin KRBTGT anahtarları, merkezi (writable) DC'lerden farklı, izole edilmiş bir anahtar setidir — bu, tasarım gereği bir güvenlik sınırıdır. Şube ofislerindeki bir RODC ele geçirilse dahi, doğrudan merkez ağdaki hesapları taklit etmek mümkün değildir; bu sınırı aşmaya çalışan araştırmalar genellikle RODC'nin "hangi hesapların parolasını önbelleğe alabileceği" (Password Replication Policy) yapılandırma hatalarına odaklanır.

---

## 5. Sınırların Ötesi: Hibrit Bulut ve Sertifika Tabanlı Kalıcılık

Geleneksel şirketler artık saf lokal Active Directory kullanmıyor; altyapılarını Azure AD Sync / Entra ID Cloud Sync ile hibrit hale getiriyorlar. Bu da kalıcılık yüzeyini lokal DC'nin çok ötesine taşıyor. Bu bölümdeki teknikler SpecterOps, Dirk-jan Mollema ve Certipy/"Certified Pre-Owned" araştırması gibi kamuya açık kaynaklarla belgelenmiştir; amacımız bu bilinen risklerin **mekanizmasını** ve **tespit/savunma** tarafını anlamaktır.

### 5.1 Azure AD Kerberos Trust (Cloud TGT) Riski

Entra ID, hibrit bir ortamda Kerberos ile bulut kaynaklarına erişimi mümkün kılmak için `AzureADKerberos` adında özel bir bilgisayar hesabı nesnesi oluşturur. Bu nesne, lokal AD ile bulut kimlik doğrulaması arasında bir köprü görevi görür. Riskin özü şudur: bu köprü nesnesinin hash'i veya ona bağlı hizmet sorumlusu (Service Principal) izinleri kötüye kullanılırsa, saldırgan lokal KRBTGT'ye hiç dokunmadan, bulut tarafından başlayan bir kimlik doğrulama zinciriyle şirket içi kaynaklara erişim kazanabilir. Bu, kalıcılık tespitinin artık yalnızca lokal DC loglarına bakarak yapılamayacağı, Entra ID audit loglarının da izlenmesi gerektiği anlamına gelir.

**Savunma açısından önemli noktalar:**
- `AzureADKerberos` hesabına ve ilişkili Service Principal'lara verilen izinler düzenli olarak gözden geçirilmeli.
- Entra ID sign-in loglarında, hibrit Kerberos akışlarına ait anormal coğrafi konum veya cihaz uyumsuzlukları izlenmeli.
- Hibrit senkronizasyon hesaplarının (Azure AD Connect / Cloud Sync hesapları) ayrıcalıkları en aza indirilmeli (least privilege).

### 5.2 Seamless SSO (AZUREADSSOACC) Hesabının Kritikliği

Microsoft'un Seamless SSO (Kesintisiz Tek Oturum Açma) mekanizması, lokal AD içinde oluşturulan `AZUREADSSOACC$` adlı bir bilgisayar hesabının Kerberos hash'ini kullanarak kullanıcıları buluta şifresiz şekilde oturum açmış gibi taşır. Bu hesap dikkat çekmeyecek kadar sıradan görünse de, hash'i ele geçirildiğinde saldırgan — teorik olarak — şirket ağı dışından bile, herhangi bir kullanıcı adına buluta yönelik sahte Kerberos biletleri üretebilir hale gelir. Bu yüzden `AZUREADSSOACC$` hesabı, pratikte KRBTGT kadar hassas bir varlık olarak ele alınmalıdır.

**Savunma açısından önemli noktalar:**
- Bu hesabın parolası, Microsoft'un önerdiği bakım döngüsüne (genellikle Azure AD Connect üzerinden otomatik/periyodik) uygun şekilde yenilenmeli.
- Hesaba erişimi olan güvenlik gruplarının üyeliği sıkı şekilde denetlenmeli.
- Conditional Access politikaları, yalnızca Kerberos biletine güvenmek yerine cihaz uyumluluğu ve konum gibi ek sinyalleri de zorunlu kılacak şekilde yapılandırılmalı.

### 5.3 AD CS ve "Golden Certificate" Kalıcılığı

AD Certificate Services (AD CS), kurumsal ortamlarda sertifika tabanlı kimlik doğrulamayı (PKINIT) mümkün kılar. Bir saldırgan Domain Admin yetkisi kazandığında, KRBTGT hash'ini yedeklemek artık tek seçenek değildir: kurumun kök Certificate Authority'sinin (CA) özel anahtarı ele geçirilirse, bu anahtarla KDC'nin her zaman güveneceği, süresi pratik olarak sınırsız sayılabilecek sahte kullanıcı sertifikaları üretilebilir. Bu sertifikalarla doğrudan bir AS-REQ gönderilerek, sanki bir akıllı kart (Smart Card) ile giriş yapılmış gibi en yüksek yetkili TGT biletleri elde edilebilir — literatürde bu senaryo "Golden Certificate" olarak anılır ve Certipy ile "Certified Pre-Owned" araştırmasında (SpecterOps, 2021) ayrıntılı şekilde belgelenmiştir.

Bu tekniğin KRBTGT tabanlı Golden Ticket'tan en kritik farkı, **kalıcılık kaynağının parola değil bir kriptografik anahtar çifti olmasıdır** — bu da klasik "KRBTGT parolasını iki kez sıfırla" savunmasını tek başına yetersiz kılar.

**Savunma açısından önemli noktalar:**
- Kök CA özel anahtarı, mümkünse HSM (Hardware Security Module) içinde saklanmalı ve erişimi çok az sayıda hesapla sınırlandırılmalı.
- AD CS şablonları (certificate templates) düzenli olarak yanlış yapılandırma (misconfiguration) taramasından geçirilmeli — Certipy gibi açık kaynak araçlar bu denetimi savunma amaçlı da kullanılabilir.
- CA'nın sertifika iptal listesi (CRL) yayın süreçleri sağlıklı çalıştığından emin olunmalı; bir ihlal şüphesinde kök CA'nın yeniden anahtarlanması (re-keying) planı hazır bulundurulmalı.

---

## 6. Savunma Perspektifi: Threat Hunting ve Tespit

İleri seviye bir kırmızı takım uzmanının, kullandığı tekniğin savunma tarafında nasıl göründüğünü de bilmesi gerekir — hem raporlama kalitesi hem de gerçekçi bir tehdit modeli için.

### 6.1 Kritik Event ID'ler

| Event ID | Anlamı | Ne aranır? |
|---|---|---|
| 4768 | TGT bilet isteği | Anormal derecede uzun geçerlilik süreleri (örn. 10 yıl), beklenmeyen şifreleme türleri |
| 4769 | TGS bilet isteği | Diamond/Sapphire Ticket tespiti için, kullanıcının normalde erişmediği servislere ani ve yetkisi şüpheli erişim talepleri |
| 4770 | Bilet yenileme | Beklenmeyen yenileme desenleri |

### 6.2 KRBTGT Parolasının Çifte Sıfırlanması

Bir Golden Ticket kalıcılığını tamamen ortadan kaldırmak için KRBTGT parolasının **art arda iki kez** sıfırlanması gerekir. Bunun nedeni, Active Directory'nin bir önceki parolayı da bir süre bellekte tutması ve bu sayede eski biletlerin "aniden patlamamasıdır" — tek seferlik bir sıfırlama, eski (sahte) biletlerin geçerliliğini otomatik olarak sonlandırmaz. Bu süreç genellikle Microsoft'un resmi `New-KrbtgtKeys.ps1` betiği veya benzeri otomasyon araçlarıyla, tekrarlama (replikasyon) süresi göz önünde bulundurularak planlanır.

### 6.3 Genel Savunma Önerileri

- KRBTGT parolasını düzenli aralıklarla (örn. 180 günde bir) proaktif olarak sıfırlayın.
- Tier modeli (Tiering) uygulayarak yönetici hesaplarının günlük iş istasyonlarında hiç oturum açmamasını sağlayın.
- LSASS belleğine erişimi kısıtlayan Credential Guard gibi mekanizmaları etkinleştirin.
- Anormal bilet ömrü ve şifreleme türü kombinasyonlarını izleyen özel SIEM kuralları yazın.

---

## 7. MITRE ATT&CK Eşlemesi

Raporlama ve içerik profesyonelliği için, bu yazıda geçen tekniklerin ATT&CK karşılıklarını tek tabloda topladık:

| Teknik | MITRE ATT&CK ID | Taktik |
|---|---|---|
| Golden Ticket | T1558.001 | Credential Access |
| Silver Ticket | T1558.002 | Credential Access |
| Diamond / Sapphire Ticket | T1558.001 (varyant) | Credential Access |
| Kerberoasting (referans) | T1558.003 | Credential Access |
| SID History Enjeksiyonu | T1134.005 | Privilege Escalation / Defense Evasion |
| AD CS Kötüye Kullanımı | T1649 | Credential Access |
| Cloud/Hibrit Kimlik Bilgisi Kötüye Kullanımı | T1552 / T1078.004 | Credential Access / Defense Evasion |

---

## 8. Sık Sorulan Sorular (SSS)

**Golden Ticket ne kadar sürede tespit edilir?**
Klasik, iyi yapılandırılmamış bir Golden Ticket bazen hiç fark edilmeyebilir; çünkü KDC ile iletişim kurmadığı için normal log akışında görünmez. Ancak olgun bir SOC, anormal bilet süresi (10 yıl gibi), beklenmeyen etype kullanımı veya "var olmayan bir oturum açma olayına rağmen kaynak erişimi" gibi ikincil sinyallerle bunu genelde saatler-günler içinde yakalar.

**Diamond Ticket, Golden Ticket'tan neden daha tehlikeli sayılır?**
Daha tehlikeli değil, daha *sessizdir*. Etkisi aynıdır (Domain Admin yetkisi), ama gerçek bir KDC etkileşimi üzerine kurulu olduğu için klasik anomali tabanlı tespit kurallarını atlatma ihtimali daha yüksektir.

**Bu teknikleri kendi şirketimde, izin almadan denedim — suç mu işlemiş olurum?**
Kısacası evet, riskli bir alandasınız. Türkiye'de TCK 243–245 maddeleri (bilişim sistemine yetkisiz erişim, sistemi engelleme/bozma, verileri değiştirme) ve pek çok ülkede benzer bilgisayar suçları mevzuatı, yazılı ve açık bir yetkilendirme (pentest sözleşmesi, "get out of jail" belgesi) olmadan yapılan bu tür işlemleri suç sayar — şirket sizin çalıştığınız yer olsa bile resmi izin şarttır. Ben avukat değilim; somut durumunuz için bir hukuk danışmanına başvurmanızı öneririm.

**OSCP sınavında bu tekniklerin hepsi çıkıyor mu?**
OSCP (OffSec PEN-200) müfredatı Golden Ticket ve Kerberoasting gibi temel/orta seviye teknikleri kapsar. Diamond/Sapphire Ticket, AD CS Golden Certificate ve hibrit bulut kalıcılığı gibi ileri konular genellikle OSCP'nin ötesinde, CRTP/CRTE veya gerçek dünya kırmızı takım operasyonları seviyesinde karşınıza çıkar — yine de kavramsal olarak bilmeniz sınavda "büyük resmi" görmenizi kolaylaştırır.

**Laboratuvar ortamı olmadan bu konuyu pratik edebilir miyim?**
Hayır, önerilmez. Ücretsiz/düşük maliyetli seçenekler: kendi bilgisayarınızda VirtualBox/VMware ile 1 DC + 1-2 istemciden oluşan küçük bir AD lab kurmak, ya da HackTheBox / TryHackMe gibi platformların yasal olarak sunduğu AD makinelerini kullanmak.

---

## 9. Kaynakça ve İleri Okuma

Video açıklamasına (description) kopyalayabileceğiniz kaynak listesi:

- SpecterOps — "Certified Pre-Owned" (AD CS saldırı yüzeyi araştırması)
- SpecterOps — Diamond Ticket ve Sapphire Ticket teknik yazıları
- Dirk-jan Mollema (dirkjanm.io) — Azure AD / Entra ID hibrit kimlik araştırmaları
- Benjamin Delpy — Mimikatz resmi GitHub deposu ve dokümantasyonu
- GhostPack / Rubeus — resmi GitHub deposu
- Certipy — AD CS denetim ve araştırma aracı, GitHub deposu
- Microsoft MSRC — güncel CVE danışma sayfaları (özellikle Kerberos/PAC ile ilgili yamalar)
- MITRE ATT&CK — T1558 (Steal or Forge Kerberos Tickets) tekniği ve alt teknikleri
- RFC 4120 — The Kerberos Network Authentication Service (V5)
- RFC 8009 — AES Encryption for Kerberos 5

> Not: Yukarıdaki kaynakları kendi araştırmanızla doğrulamanızı öneririm; bağlantı adresleri zamanla değişebilir ve bu liste hafızadan derlenmiştir.

---

## Sonuç

Kerberos bilet sahteciliği, tek bir "hack" değil; protokolün güven varsayımlarını adım adım delen bir teknik ailesidir. Golden Ticket ile başlayıp Silver Ticket'ın hedef odaklılığını, Diamond/Sapphire Ticket'ın tespit atlatma inceliğini ve nihayetinde CVE tabanlı protokol açıklarını anlamak, hem OSCP gibi sertifikalarda hem de gerçek dünya kırmızı takım operasyonlarında sizi bir adım öne taşır. Ancak unutmayın: bu bilginin değeri, onu yalnızca yetkilendirilmiş ortamlarda, sorumlu ve etik bir çerçevede kullanmanızla ölçülür.
