# DirFuzzer

EnhancedDirFuzzer adalah alat **directory and file fuzzing** yang powerful dan fleksibel untuk menemukan direktori, file, dan konten tersembunyi di sebuah website. Dibangun dengan Python, alat ini mendukung multi-threading, filter status HTTP, teknologi deteksi, export laporan HTML, dan banyak fitur lainnya.

---

## Fitur Utama

- Scanning direktori/file menggunakan wordlist custom
- Multi-threaded dengan pengaturan jumlah thread
- Filter status code (include/exclude)
- Support proxy dan custom User-Agent
- Export laporan hasil scan dalam format HTML yang rapi
- Support crawling mode (eksperimental)
- Stealth mode untuk menghindari deteksi
- Support resume scan dan save response
- Teknologi deteksi berbasis header HTTP
- Output warna di terminal untuk hasil yang jelas dan mudah dibaca
- Dan banyak lagi!

---

## Instalasi
Pastikan Python 3.6+ sudah terpasang di sistem kamu.

1. Clone repository ini:

```bash
git clone https://github.com/SatrioUN/fuzzing-dir
cd fuzzing-dir
Install dependency 
pip install -r requirements.txt

Penggunaan:
python3 dir.py URL -w wordlist.txt [options]
Contoh:
python3 dir.py https://example.com -w wordlist.txt --threads 30 --export-html --verbose

Opsi dan Parameter:
| Opsi                     | Deskripsi                                       | Contoh                          |
| ------------------------ | ----------------------------------------------- | ------------------------------- |
| `-w, --wordlist`         | Path ke file wordlist                           | `-w wordlist.txt`               |
| `-t, --threads`          | Jumlah thread concurrency                       | `--threads 50`                  |
| `--timeout`              | Timeout request (detik)                         | `--timeout 10`                  |
| `--retries`              | Jumlah retry request gagal                      | `--retries 3`                   |
| `--rate-limit`           | Limit request per detik                         | `--rate-limit 15`               |
| `-o, --output`           | File output plain text                          | `-o hasil.txt`                  |
| `--output-json`          | File output JSON                                | `--output-json hasil.json`      |
| `--user-agent`           | Custom header User-Agent                        | `--user-agent "MyAgent/1.0"`    |
| `--proxy`                | Proxy HTTP/HTTPS                                | `--proxy http://127.0.0.1:8080` |
| `--receiver`             | Mode interaktif receiver                        | `--receiver`                    |
| `--crawl`                | Enable mode crawling                            | `--crawl`                       |
| `--max-crawl-depth`      | Maksimal kedalaman crawl                        | `--max-crawl-depth 3`           |
| `--verbose`              | Output verbose di terminal                      | `--verbose`                     |
| `--recursive`            | Scan recursive direktori                        | `--recursive`                   |
| `--extensions`           | Ekstensi file yang dicoba (comma separated)     | `--extensions .php,.html`       |
| `--exclude-status`       | Status HTTP yang dikecualikan (comma separated) | `--exclude-status 404,403`      |
| `--include-status`       | Hanya status HTTP yang diikutkan                | `--include-status 200,301`      |
| `--follow-redirects`     | Ikuti redirect HTTP                             | `--follow-redirects`            |
| `--no-verify-ssl`        | Disable verifikasi SSL certificate              | `--no-verify-ssl`               |
| `--random-agent`         | Gunakan User-Agent acak per request             | `--random-agent`                |
| `--stealth`              | Mode stealth (delay random)                     | `--stealth`                     |
| `--brute-force`          | Mode brute force (fitur pengembangan)           | `--brute-force`                 |
| `--content-discovery`    | Temukan konten sensitif                         | `--content-discovery`           |
| `--technology-detection` | Deteksi teknologi server                        | `--technology-detection`        |
| `--smart-filter`         | Filter false positive pintar                    | `--smart-filter`                |
| `--export-html`          | Export hasil ke laporan HTML                    | `--export-html`                 |
| `--resume`               | Resume scan sebelumnya jika ada                 | `--resume`                      |
| `--save-responses`       | Simpan response HTTP ke disk                    | `--save-responses`              |

Output Laporan:
Jika menggunakan opsi --export-html, 
hasil scan akan disimpan dalam file HTML dengan nama seperti:
dir_report_<hasil>.html
Laporan ini berisi tabel hasil scan lengkap dengan status HTTP
,tipe file/directory, 
ukuran, tipe konten, teknologi terdeteksi, dan timestamp.

Kontak
Jika ada pertanyaan atau request fitur, hubungi:
instagram:@rioocns
