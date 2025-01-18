# Amnezichat Protokolü

## Genel Bakış
Amnezichat, hiçbir log kaydının tutulmamasını ve tüm mesaj verilerinin yalnızca sunucunun RAM'inde saklanmasını sağlamak amacıyla tasarlanmış güvenli, gizliliğe odaklanmış bir mesajlaşma protokolüdür. Protokol, güçlü uçtan uca şifreleme, forward secrecy ve trafik analizi savunması sağlar ve kuantum direncine sahip kriptografik teknikler kullanır.

## Kriptografik Bileşenler
- **Kimlik Doğrulama:** EdDSA & Dilithium5
- **Anahtar Değişimi:** ECDH & Kyber1024
- **Şifreleme:** ChaCha20-Poly1305
- **Anahtar Oluşturma Fonksiyonu (KDF):** Argon2id
- **Veri Depolama Koruması:** Yerel kimlik anahtarları, ChaCha20-Poly1305 ile şifrelenir ve Argon2id kullanılarak kullanıcı tarafından belirlenen bir parola ile güvence altına alınır.

## Hibrit Anahtar Takası Diyagramı:

![hybrid_key_exchange](hybrid_key_exchange.png)

## Protokol Tasarımı
### 1. Oturum Oluşturma
- İstemciler, geçici anahtar çiftleri oluşturarak bir oturum başlatır.
- ECDH ve Kyber1024 kullanılarak bir anahtar değişimi yapılır ve ortak bir gizli anahtar oluşturulur.
- Her iki taraf, EdDSA ve Dilithium5 imzaları ile kimlik doğrulaması yapar.
- Ortak gizli anahtardan bir oturum anahtarı, kriptografik bir hash fonksiyonu kullanılarak oluşturulur.

### 2. Güvenli Mesajlaşma
- Her mesaj, oturum anahtarı ile ChaCha20-Poly1305 kullanılarak şifrelenir.
- Forward ve backward secrecy, periyodik olarak yeni geçici anahtarlar üretilerek sağlanır.
- Mesajlar, trafik analizi saldırılarını engellemek amacıyla sabit bir uzunluğa padding yapılır.
- Yapay zeka destekli Trafik Analizi'ne (DAITA) karşı koymak için şifreli sahte veri rastgele aralıklarla gönderilir.

### 3. Grup Mesajlaşma
- Argon2id kullanılarak bir oda şifresinden türetilen Önceden Paylaşılmış Anahtar (PSK), grup mesajlarını şifrelemek için kullanılır.
- Bir grup içindeki her istemci, mesaj şifreleme için ortak bir şifreleme anahtarı paylaşır.

### 4. Veri Saklama Politikası
- Mesajlar yalnızca RAM'de saklanır ve 24 saat sonra otomatik olarak silinir.
- Sunucu tarafından kalıcı loglar veya başka veriler saklanmaz.
- Sunucunun yeniden başlatılması tüm verilerin silinmesine yol açar.

## Ağ Katmanı
- Tüm trafik, anonimlik sağlamak amacıyla varsayılan olarak Tor/I2P ağı üzerinden yönlendirilir.
- Onion/Garlic yönlendirme, IP adreslerinin gizli kalmasını sağlar.
- Mesajlar, korelasyon saldırılarını önlemek için rastgele zamanlamalarla şifreli paketlere kapsüllenir.

## Güvenlik Hususları
- Kullanıcılar, anahtarların çalınmasını engellemek için yerel cihazlarının güvende olduğundan emin olmalıdır.
- Kimlik anahtarlarını şifrelemek için güçlü parolalar kullanılmalıdır.

## Lisans
Amnezichat, GPLv3 Lisansı altında dağıtılmaktadır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

## Destek & Bağışlar
Projeye destek olmak için bağış yapmayı düşünebilirsiniz:
- **Monero (XMR):** 88a68f2oEPdiHiPTmCc3ap5CmXsPc33kXJoWVCZMPTgWFoAhhuicJLufdF1zcbaXhrL3sXaXcyjaTaTtcG1CskB4Jc9yyLV
- **Bitcoin (BTC):** bc1qn42pv68l6erl7vsh3ay00z8j0qvg3jrg2fnqv9
