
## Proje Açıklaması
Bu proje, büyük miktarda şifre verisini işleyerek indeksleyen ve arama yapmaya olanak tanıyan bir Java uygulamasıdır. Uygulama, verilen klasörlerdeki şifreleri okuyarak işlenmiş hale getirir, şifrelerin çeşitli hash algoritmaları ile özetlerini oluşturur ve bu verileri indeksleyerek daha hızlı erişim sağlar. Ayrıca, belirli bir şifrenin indekslenmiş veriler içinde olup olmadığını arayabilir ve bulunamayan şifreleri indekse ekleyebilir.

## Kullanılan Teknolojiler ve Öğrenilen Konular
Bu proje kapsamında aşağıdaki Java yapıları ve kavramları aktif olarak kullanılmış ve pekiştirilmiştir:
### 1. **Dosya İşlemleri (File I/O)**
- `File`, `FileReader`, `FileWriter`, `BufferedReader`, `BufferedWriter` gibi sınıflar kullanılarak dosya okuma, yazma ve silme işlemleri gerçekleştirilmiştir.
- Unprocessed klasöründeki şifreler okunarak işlenmiş şifreler başka bir dosyada saklanmıştır.
- Dosya içeriklerinin temizlenmesi işlemi gerçekleştirilmiştir.
### 2. **Hashleme Algoritmaları (Message Digest)**
- `MessageDigest` sınıfı ile **MD5, SHA-1 ve SHA-256** hash fonksiyonları kullanılarak her şifrenin güvenli özetleri oluşturulmuştur.
- Güvenli depolama için hash fonksiyonlarının nasıl çalıştığı incelenmiş ve uygulanmıştır.
### 3. **Veri Yapıları ve Koleksiyonlar**
- **Set (HashSet)**: Daha önce işlenmiş şifreleri saklamak ve tekrar edenleri önlemek için kullanılmıştır.
- **Map (HashMap)**: Farklı harf gruplarına göre dosyaları yönetmek amacıyla kullanılmıştır.
### 4. **Dizin (Index) Yapısı**
- Şifreleri ilk harflerine göre dizinleyerek indeksleme mantığı oluşturulmuştur.
- Büyük harfler ve özel karakterler için özel klasörler kullanılarak düzenli bir dosya yapısı oluşturulmuştur.
### 5. **Kullanıcı Girişi ve Menü Yönetimi**
- `Scanner` kullanılarak kullanıcıdan giriş alınmış, uygun işlemler başlatılmıştır.
- Kullanıcı, şifreleri işleyebilir, belirli bir şifreyi arayabilir veya çıkış yapabilir.
### 6. **Exception Handling (Hata Yönetimi)**
- **`try-catch-finally`** blokları ile dosya işlemlerinde oluşabilecek hatalar yakalanmış ve uygun hata mesajları döndürülmüştür.
- Örneğin, eksik dosyalar veya yanlış indeks klasörleri gibi durumlar için hata kontrolleri eklenmiştir.

## Proje Yapısı
```plaintext
File_Project/
│── Unprocessed-Passwords/   # İşlenmemiş şifrelerin bulunduğu klasör
│── Processed/               # İşlenmiş şifrelerin kaydedildiği klasör
│   └── Processed.txt        # Tüm işlenmiş şifrelerin saklandığı dosya
│── Index/                   # Şifrelerin indekslendiği klasör
│   ├── a/                   # 'a' harfiyle başlayan şifreler burada saklanır
│   ├── b/                   # 'b' harfiyle başlayan şifreler burada saklanır
│   ├── Buyuk_harfler/       # Büyük harfle başlayan şifreler burada saklanır
│   │   ├── A/               # 'A' harfiyle başlayan şifreler burada saklanır
│   │   ├── B/               # 'B' harfiyle başlayan şifreler burada saklanır
│   └── tanimsiz/            # Özel karakterle başlayan şifreler burada saklanır
└── PasswordProcessor.java    # Uygulamanın ana Java dosyası
```
## Sonuç
Bu proje, Java ile dosya işlemleri, veri yapıları, hashing algoritmaları ve indeksleme mantığı gibi birçok önemli yazılım geliştirme konseptini pekiştirmek için geliştirilmiştir. Gerçek dünya senaryolarında büyük veri kümelerinin işlenmesi, güvenli veri saklama ve hızlı erişim için indeksleme teknikleri gibi kavramları uygulamaya koyarak daha derin bir anlayış kazanılmıştır.
