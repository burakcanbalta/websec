**LAPS** ve **gMSA**, Active Directory'nin iki kronik hastalığına — yerel yönetici şifrelerinin tekrar kullanımı ve servis hesaplarının statik/zayıf şifreleri — Microsoft'un getirdiği resmi çözümlerdir. İkisi de doğru yapılandırıldığında gerçekten etkilidir; ikisi de yanlış yapılandırıldığında ise **tam olarak önlemek için var oldukları saldırıyı, çok daha zarif bir şekilde** geri getirir. Bu ironi, bu yazının ana teması: savunma mekanizmasının kendisi, yanlış ACL veya yanlış grup üyeliğiyle, bir saldırganın elindeki en güçlü keşif/yetki yükseltme aracına dönüşebilir.

Bu yazı, LAPS'ın neden var olduğundan ve nasıl çalıştığından başlayıp, ACL/yetkilendirme zafiyetlerine, gMSA'nın kriptografik türetme mekanizmasına, `PrincipalsAllowedToRetrieveManagedPassword` yanlış yapılandırmalarına, KDS Root Key ele geçirilmesiyle yapılan **Golden gMSA** saldırısına ve son olarak Windows Server 2025'in dMSA özelliğindeki gerçek dünya 0-day'i **BadSuccessor**'a kadar ilerliyor.

---

## 1. LAPS Neden Var? — Çözdüğü Problem

Klasik bir AD ortamında, imaj/GPO ile dağıtılan makinelerin **yerel Administrator hesabı** genellikle aynı şifreyi paylaşır — bu operasyonel kolaylık için yapılır, ama güvenlik açısından bir felakettir. Bir saldırgan **tek bir makinenin** yerel admin hash'ini ele geçirdiğinde (mimikatz, SAM dump), bu hash'i **Pass-the-Hash** ile ortamdaki **her makinede** deneyebilir — çünkü hepsi aynı şifreyi paylaşır. Tek bir zayıf halka, tüm workstation filosunun ele geçirilmesi anlamına gelir.

**LAPS (Local Administrator Password Solution)**, bu sorunu her makinenin yerel admin şifresini **rastgele, birbirinden bağımsız ve periyodik olarak rotate edilen** bir değere çevirerek çözer. Şifre, Active Directory'de o bilgisayar nesnesinin bir özniteliğinde saklanır ve **sadece yetkili kişiler/gruplar** tarafından okunabilir.

---

## 2. LAPS Mimarisi

### 2.1 Legacy LAPS (v1)

Client-side extension (CSE), her rotate döngüsünde yeni bir şifre üretir ve bunu bilgisayar nesnesinin **`ms-Mcs-AdmPwd`** özniteliğine **düz metin olarak** yazar (LDAPS/Kerberos şifreli bağlantı üzerinden taşınır, ama AD veritabanında düz metin olarak durur — sadece ACL ile korunur). İkinci bir öznitelik olan **`ms-Mcs-AdmPwdExpirationTime`**, bir sonraki rotasyon zamanını tutar.

```
ms-Mcs-AdmPwd          → "kX8!vQ2#pL9zR"   (düz metin, sadece ACL korur)
ms-Mcs-AdmPwdExpirationTime → 133456789000000000
```

### 2.2 Windows LAPS (v2, 2023+)

Microsoft'un yerleşik hale getirdiği yeni sürüm, kriptografik olarak çok daha sağlam bir yaklaşım kullanır:

* **`msLAPS-Password`**: JSON formatında, düz metin şifreyi taşır (v1'e benzer, geriye dönük uyumluluk için).
* **`msLAPS-EncryptedPassword`**: Şifre, **AES ile şifrelenmiş** olarak saklanır — anahtar, **KDS Root Key**'den türetilir (gMSA'nın da kullandığı aynı altyapı, bkz. Bölüm 4).
* **`msLAPS-EncryptedPasswordHistory`**: Geçmiş şifrelerin şifreli kaydı — parola geçmişini denetlemeye izin verir.

Windows LAPS ayrıca **DSRM (Directory Services Restore Mode) şifresini** de rotate edebilir ve yerel hesap adının kendisini bile rastgeleleştirebilir (`msLAPS-AccountName` desteğiyle) — bu, saldırganın "yerel admin hesabının adı hep Administrator" varsayımını da kırar.

---

## 3. LAPS Zafiyetleri

### 3.1 Aşırı Geniş Okuma Yetkisi (En Yaygın Hata)

LAPS'ın kurulumu sırasında, hangi grupların şifreyi **okuyabileceğini** (`Read Property` üzerinde `ms-Mcs-AdmPwd`/`msLAPS-Password`) belirleyen bir ACL delegasyonu yapılır. Bu adım genellikle "Helpdesk grubuna okuma izni ver" gibi iyi niyetli ama **gereğinden geniş** bir kapsamla yapılır — örneğin OU bazında değil, **domain kökünde** delege edilir, ya da "Authenticated Users" gibi çok geniş bir gruba yanlışlıkla `All Extended Rights` verilir.

```powershell
# BloodHound / PowerView ile kimlerin LAPS şifresini okuyabildiğini haritalama
Get-DomainObjectAcl -SearchBase "OU=Workstations,DC=corp,DC=local" |
  Where-Object { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" }
```

BloodHound'da bu ilişki doğrudan bir **`ReadLAPSPassword`** kenarı (edge) olarak görünür — saldırgan, ele geçirdiği herhangi bir kullanıcının bu kenarla hangi bilgisayarların şifresine erişebildiğini saniyeler içinde görebilir. Bu, LAPS ile ilgili gerçek dünyada karşılaşılan **en yaygın** zafiyettir; teknoloji kırılmaz, ama etrafındaki yetkilendirme neredeyse her zaman fazla cömerttir.

### 3.2 Confidentiality Bit Eksikliği ve DCSync Üzerinden Sızıntı

Active Directory'de bazı öznitelikler "gizli" (confidential) olarak işaretlenebilir — bu işaretleme, **replikasyon** sırasında bile ekstra bir kontrol katmanı ekler. LAPS kurulumu doğru yapılmamışsa (şema uzantısı sırasında confidentiality bit ayarlanmamışsa), `ms-Mcs-AdmPwd` özniteliği bu korumadan **muaf** kalabilir.

Sonuç: `Replicating Directory Changes` ve `Replicating Directory Changes All` haklarına sahip biri (klasik **DCSync** senaryosu — genellikle Domain Admins/Domain Controllers grubuna ait olur, ama yanlış delege edilmiş olabilir) doğrudan explicit bir "LAPS şifresini oku" iznine sahip olmasa bile, **replikasyon protokolü üzerinden** şifreyi çekebilir — çünkü replikasyon, confidential olarak işaretlenmemiş özniteliklere karşı standart ACL kontrolünü aynı sıkılıkta uygulamaz.

### 3.3 Rotasyon Penceresindeki Yarış

LAPS varsayılan rotasyon aralığı genellikle 30 gündür (yapılandırılabilir). Bir saldırgan, şifreyi rotasyondan **hemen önce** elde ederse, bu şifre hâlâ günlerce/haftalarca geçerli kalabilir — LAPS "sürekli rotasyon" sağlar ama "anlık geçersiz kılma" sağlamaz. Bir ihlal tespit edildiğinde, etkilenen makinelerde **manuel/acil rotasyon tetiklemek** (`Invoke-LapsPolicyProcessing` veya `Reset-LapsPassword`) bu pencereyi kapatmanın tek yoludur.

### 3.4 Legacy CSE Debug Log Sızıntısı

Eski LAPS client-side extension sürümlerinde, belirli hata ayıklama (debug/verbose) günlükleme seviyeleri etkinleştirildiğinde, rotasyon işlemi sırasında şifrenin **düz metin olarak event log'a veya CSE log dosyasına** yazıldığı, geçmişte tespit edilmiş bir davranış kalıbıdır. Bu, "gizli tutulması gereken bir sırrın, teşhis amaçlı bir günlükleme yoluyla dışarı sızması" örneğinin klasik bir versiyonudur — LAPS'a özgü olmayan ama LAPS bağlamında özellikle yıkıcı bir hata sınıfıdır. Prensip: **hiçbir sır, hata ayıklama günlüğüne asla yazılmamalıdır**, bu ilke özellikle LAPS/gMSA gibi kimlik bilgisi taşıyan bileşenlerde katı şekilde uygulanmalıdır.

---

## 4. gMSA Neden Var? — Kerberoasting'e Mimari Cevap

Kerberoasting yazımızda detaylandırdığımız gibi, klasik servis hesaplarının en büyük zayıflığı **insan tarafından belirlenen, nadiren değişen şifreleridir.** **gMSA (group Managed Service Account)**, bu sorunu kökten çözer: şifre insan tarafından hiç belirlenmez, hiç bilinmez, ve **otomatik olarak periyodik rotate edilir** (varsayılan 30 gün).

### 4.1 Şifre Nasıl Üretilir?

gMSA şifresi, klasik anlamda "saklanmaz" — **her istendiğinde türetilir.** Türetme, bir **KDS Root Key** (Key Distribution Service Root Key — domain genelinde, Domain Controller'larda saklanan bir kök materyal) kullanılarak yapılır:

```
gMSA Şifresi = KDF(KDS Root Key, gMSA'nın SID'i, geçerli zaman penceresi)
```

Bu, LAPS v2'nin şifreyi şifrelemek için kullandığı **aynı KDS altyapısını** paylaşır — iki mekanizma da nihayetinde aynı kök sırra dayanır.

### 4.2 `msDS-ManagedPassword` Özniteliği

gMSA'nın güncel şifresi, `msDS-ManagedPassword` özniteliğinde **binary blob** olarak tutulur (yapı: `MSDS-MANAGEDPASSWORD_BLOB`). Bu özniteliği **kim okuyabilir**, `PrincipalsAllowedToRetrieveManagedPassword` özniteliğinde tanımlanan gruplar/bilgisayar hesapları tarafından belirlenir — genellikle "bu gMSA'yı hangi sunucular servis olarak çalıştırabilir" listesidir.

```powershell
# Bir gMSA'nın kimler tarafından okunabildiğini kontrol etme
Get-ADServiceAccount -Identity svc-web-gmsa -Properties PrincipalsAllowedToRetrieveManagedPassword
```

---

## 5. gMSA Zafiyetleri

### 5.1 Aşırı Geniş `PrincipalsAllowedToRetrieveManagedPassword`

Tıpkı LAPS'taki ACL hatasının bir yansıması gibi, bu özniteliğe **gereğinden geniş** bir grup (örneğin "Domain Computers" gibi neredeyse her bilgisayarı kapsayan bir grup) eklendiğinde, o gruba üye **herhangi bir bilgisayar hesabı** gMSA'nın güncel şifresini LDAP üzerinden sorgulayıp çözebilir.

```bash
# GMSADumper.py ile yetkili bir bilgisayar hesabı context'inden gMSA şifresini çekme
python3 gMSADumper.py -u 'COMPUTER$' -p 'hash' -d corp.local
```

```powershell
# DSInternals ile aynı işlem, blob'u decode ederek NTLM hash üretimi
Get-ADServiceAccount -Identity svc-web-gmsa -Properties 'msDS-ManagedPassword' |
  ConvertFrom-ADManagedPasswordBlob
```

Bir saldırgan, `PrincipalsAllowedToRetrieveManagedPassword` listesindeki **herhangi bir bilgisayar hesabının** kontrolünü ele geçirdiğinde (örneğin o makinede local admin olarak), doğrudan gMSA'nın güncel parolasını/NTLM hash'ini elde edebilir — kırmaya bile gerek kalmadan, çünkü değer türetilmiş ama **açık formatta** sorgulanabilir durumdadır.

### 5.2 Golden gMSA — KDS Root Key Ele Geçirilmesi

Bu, Golden Ticket saldırısının gMSA dünyasındaki doğrudan karşılığıdır. Eğer bir saldırgan **bir kez** Domain Admin (veya DCSync yetkisi) elde ederse, KDS Root Key materyalini AD'den çekebilir:

```powershell
# KDS Root Key'i çekme (Domain Admin/DCSync yetkisi gerektirir)
Get-KdsRootKey
```

Bu kök materyale sahip olduktan sonra, saldırgan **artık Domain Controller'a hiç dokunmadan**, ortamdaki **herhangi bir gMSA'nın** (geçmiş, mevcut ve hatta gelecekteki rotasyon dönemlerindeki) şifresini **offline olarak** matematiksel türetme ile hesaplayabilir — çünkü türetme fonksiyonu deterministiktir ve girdileri (kök anahtar, SID, zaman penceresi) bilinir hale gelmiştir.

**Bunun önemi:** Klasik bir "Domain Admin ele geçirildi, şifreler değiştirildi, ihlal kapatıldı" senaryosunda bile, saldırgan **daha önce çektiği KDS Root Key ile**, şifreler rotate edildikten **sonra bile**, yeni gMSA şifrelerini önceden hesaplayabilir — bu, klasik Golden Ticket'ın `krbtgt` şifresini değiştirmenin (tek başına) yeterli olmamasıyla aynı kalıcılık sorununu taşır. Kök materyalin kendisi rotate edilmediği sürece, bu "kalıcı arka kapı" geçerliliğini korur.

### 5.3 Computer Object Devralma Üzerinden Yanal Hareket

Bir gMSA, belirli bilgisayar hesapları tarafından kullanılacak şekilde yapılandırıldığında, o **bilgisayar hesabının kendisi** saldırı yüzeyinin bir parçası olur. RBCD (Resource-Based Constrained Delegation) veya bir bilgisayar nesnesi üzerinde `GenericWrite` gibi bir ACL zafiyeti varsa, saldırgan önce o bilgisayar hesabının kimliğini ele geçirip, ardından bu kimlik üzerinden gMSA'nın şifresini sorgulayabilir — Kerberoasting yazımızdaki delegasyon zincirleme mantığıyla doğrudan aynı desendir, sadece hedef artık statik bir şifre değil türetilmiş bir gMSA parolasıdır.

---

## 6. Araştırma Seviyesi: BadSuccessor (dMSA) — CVE-2025-53779

Windows Server 2025, gMSA'nın bir sonraki evrimi olarak **dMSA (delegated Managed Service Account)** özelliğini tanıttı — amacı, eski/unmanaged servis hesaplarının **sorunsuz şekilde** dMSA'ya "göç ettirilmesini" (migration) sağlamaktı. Akamai araştırmacısı Yuval Gordon tarafından keşfedilen **BadSuccessor** tekniği, bu göç mekanizmasındaki bir yetki devri hatasını istismar ediyordu.

### 6.1 Zafiyetin Mekanizması

dMSA'nın "migration" özelliği, bir dMSA'nın `msDS-ManagedAccountPrecededByLink` özniteliği aracılığıyla **var olan bir hesabın yerini aldığını** belirtmesine izin veriyordu. Sorun şuydu: KDC, bu bağlantıyı gördüğünde, gerçek bir göçün tamamlandığını **doğrulamadan**, dMSA'yı sanki bağlandığı hesabın **doğrudan devamıymış gibi** kabul ediyordu — kimlik doğrulama sırasında üretilen PAC (Privilege Attribute Certificate), bağlanılan hesabın **tüm ayrıcalıklarını** taşıyordu.

Pratik sonucu: bir OU üzerinde sadece **`CreateChild`** yetkisine sahip (yani yeni bir nesne oluşturabilen) sıradan bir kullanıcı bile, kendi dMSA'sını oluşturup bunu **Domain Admin gibi** yüksek yetkili bir hesaba "bağlayarak" (tek taraflı, gerçek bir migration onayı olmadan), o hesabın **tüm yetkilerini anında devralabiliyordu.** Akamai'nin incelediği ortamların **%91'inde**, Domain Admin olmayan en az bir kullanıcının bu saldırıyı gerçekleştirebilecek izinlere sahip olduğu tespit edildi — ve bu, varsayılan (default) yapılandırmada geçerliydi.

```powershell
# Kavramsal akış: saldırının PowerView ile OU yetkisi tespiti
Get-DomainObjectAcl -SearchBase "OU=ServiceAccounts,DC=corp,DC=local" |
  Where-Object { $_.ActiveDirectoryRights -match "CreateChild" }
```

Kritik nokta: bu saldırı için ortamda **gerçekten dMSA kullanılıyor olması bile gerekmiyordu** — sadece domain'de **bir tane** Windows Server 2025 Domain Controller bulunması, dMSA özelliğini fiilen aktif hale getirmeye yetiyordu.

### 6.2 Yama Sonrası Durum

Microsoft, **CVE-2025-53779** kimliğiyle takip edilen bu açığı 10.0.26100.4851 ve sonrası build'lerde yamaladı — düzeltme, dMSA-hedef hesap bağlantısının artık **karşılıklı (mutual) bir eşleşme** gerektirmesi, yani tek taraflı bir "bağlanma" beyanının artık yetki devri için yeterli olmamasıdır. Ancak Akamai'nin takip araştırması, doğrudan yetki yükseltme yolunun kapandığını ama **dMSA/migration mekanizmasının kendisinin** hâlâ dikkatli izlenmesi gereken bir teknik yüzey olarak kaldığını gösteriyor — "bir açık kapanır, ama teknik bir zafiyet sınıfı olarak akılda kalır" prensibinin güncel bir örneği.

---

## 7. Tespit — Hangi Sinyallere Bakılmalı?

| Sinyal | Anlamı |
|---|---|
| `ms-Mcs-AdmPwd`/`msLAPS-Password` üzerinde okuma yapan geniş/beklenmeyen gruplar | Aşırı delege edilmiş LAPS okuma yetkisi |
| Confidentiality bit'i kontrol edilmemiş LAPS şeması | DCSync üzerinden dolaylı sızıntı riski |
| `PrincipalsAllowedToRetrieveManagedPassword` içinde geniş kapsamlı gruplar (`Domain Computers` gibi) | gMSA şifresinin çok sayıda hesap tarafından okunabilmesi |
| `Get-KdsRootKey` çağrısı / KDS container'a erişim event'leri | Golden gMSA hazırlığı olabilir |
| dMSA nesnesi oluşturma + `msDS-ManagedAccountPrecededByLink` değişikliği (Event ID 5136) | BadSuccessor tarzı migration istismarı göstergesi |
| OU üzerinde `CreateChild` yetkisine sahip beklenmedik/düşük yetkili hesaplar | dMSA/gMSA oluşturma yoluyla yetki yükseltme potansiyeli |

---

## Savunma — Kalıcı Çözümler

**LAPS için:** Okuma yetkisi delegasyonları **OU bazında, en dar kapsamda** yapılmalı; `ms-Mcs-AdmPwd`/`msLAPS-Password` özniteliklerinin **confidential** olarak işaretlendiği şema seviyesinde doğrulanmalı; mümkün olan her yerde Windows LAPS v2'ye (AES şifreli, DSRM rotasyonu destekli) geçilmeli; ihlal sonrası **acil rotasyon** prosedürü tanımlı olmalı.

**gMSA için:** `PrincipalsAllowedToRetrieveManagedPassword`, sadece **gerçekten o servisi çalıştıran** bilgisayar hesaplarıyla sınırlı tutulmalı, asla geniş/genel gruplara verilmemeli; KDS Root Key erişimi **Tier 0** seviyesinde korunmalı ve DCSync yetkisi olan hesap sayısı minimumda tutulmalı; bir ihlal sonrası, sadece gMSA şifrelerini değil **KDS Root Key'i de** rotate etmek (ve eski anahtarların geçerlilik süresini yönetmek) değerlendirilmeli.

**dMSA/BadSuccessor için:** Domain Controller'lar Windows Server 2025 ise CVE-2025-53779 yaması (10.0.26100.4851+) uygulanmalı; OU'lar ve container'lar üzerindeki `CreateChild` ve dMSA nesnelerini değiştirme yetkileri sadece Tier 0 yöneticileriyle sınırlandırılmalı; `msDS-ManagedAccountPrecededByLink` değişiklikleri (Event ID 5136) aktif olarak izlenmeli.

**Genel prensip:** LAPS ve gMSA, **kriptografik olarak** sağlam mekanizmalardır — kırılan neredeyse hiçbir zaman matematik değil, etraflarına verilen **yetkilendirme kapsamıdır.** Her iki sistemde de "kim okuyabilir/kim türetebilir" sorusunun cevabı, mümkün olan en dar kümeye indirgenmelidir.

---

## Yaygın Senaryolar

* Aşırı geniş LAPS okuma yetkisi ile şifre sızıntısı
  BloodHound `ReadLAPSPassword` kenarı → doğrudan yerel admin şifresi

* Confidential bit eksikliği ile DCSync üzerinden LAPS şifresi çekme
  `Replicating Directory Changes` yetkisiyle `ms-Mcs-AdmPwd`'nin replikasyon üzerinden sızması

* Aşırı geniş `PrincipalsAllowedToRetrieveManagedPassword` ile gMSA ele geçirme
  `GMSADumper.py` ile herhangi bir yetkili bilgisayar hesabından servis parolası çekme

* Golden gMSA ile kalıcı erişim
  KDS Root Key'in bir kez sızdırılması → tüm gMSA şifrelerinin gelecekte de offline hesaplanabilmesi

* BadSuccessor ile anlık Domain Admin ele geçirme
  Bir OU'da `CreateChild` yetkisiyle dMSA oluşturup Domain Admin hesabına "bağlama" → PAC üzerinden tam yetki devralma

---
