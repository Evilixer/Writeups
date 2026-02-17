---

Team Name: UK{Cy63r$}
Challenges solved: 9
Challenge Name: **Two doors
Category: Miscellaneous
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description:
This challenge required tracking down a flag hidden in a Discord moderator's profile picture, starting from a broken URL.

---

Step 1: The Broken Link
The challenge provided the following URL:
https://chatgpt.com/share/6990cbe8-60d4-8010-ac07-7e9c6eb9d98f
Navigating to it returned a 404 error. Rather than giving up, I noticed the URL structure and attempted to swap the last two characters of the share ID (8f → f8 or similar), which revealed a valid, accessible shared ChatGPT conversation.
Step 2: Extracting Clues from the Chat
The recovered conversation contained a clue pointing to Discord, specifically referencing a moderator account:
MOD Name: Seshan
Discord Username: vividverse1625

Step 3: Discord Profile Investigation
Searching for vividverse1625 on Discord and navigating to their profile revealed that the user held a Moderator role. The profile picture (avatar) was identified as the flag location.
Examining the avatar closely, the flag was embedded in the image text/design.
Flag: BPCTF{birthday_gift_from_atlee}
Takeaway
Don't assume a 404 error means a broken link in these challenges. Try simple modifications like swapping characters, changing case, or adjusting IDs before exploring other options.
Shared links can reveal sensitive data. Publicly sharing ChatGPT conversations risks exposing private information. In CTF events, such links often serve as clues.

Challenge Name: **Time Stramp
Category: Miscellaneous
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description:
A 2000-line log file system.log was provided. On the surface it seems like routine system noise ,heartbeats, cache refreshes, scheduler ticks. The real challenge was recognizing that the signal was hidden in the pattern, not the content.

---

Step 1: Drowning in Noise
Opening system.log reveals roughly 2000 lines of DEBUG level entries that all look like this:
[14:03] DEBUG heartbeat ok
[14:07] DEBUG cache refresh complete
[14:11] DEBUG scheduler tick
A completely normal-looking log. The obvious instinct is to grep for anything unusual and that's exactly the right move.
Step 2: Spotting the Anomaly - The :25 Minute Marker
Filtering specifically for INFO level entries immediately reduces the noise dramatically, down to just 21 lines. But the real pattern reveals itself when you look at the timestamps:
[00:25] INFO  payload=f
[02:25] INFO  payload={
[03:25] INFO  payload=b
[04:25] INFO  payload=a
[06:25] INFO  payload=}
[07:25] INFO  payload=c
[09:25] INFO  payload=k
[11:25] INFO  payload=_
[15:25] INFO  payload=b
[18:25] INFO  payload=p
[21:25] INFO  payload=c
[22:25] INFO  payload=t
...
Every single INFO event fires at exactly :25 past the hour  a deliberate and unnatural timing anomaly that no real system would produce. The challengedescription, "Hidden in Timeframes", pointed directly here.
Step 3: Assembling the Flag
"Follow the trail of what history hides" is a nudge to think about ordering. Reading the payload characters in chronological timestamp order and assembling them sequentially spells out the flag:
The note back_to_future starts here at [03:25] was a subtle in-flag easter egg hinting that the flag content literally begins at that entry.
Flag: BPCTF{back_to_future}
Solve Script
import re
flag_chars = []
with open("system.log", "r") as f:
    for line in f:
        if "INFO" in line and ":25]" in line:
            match = re.search(r'payload=(\\S)', line)
            if match:
                flag_chars.append((line.strip(), match.group(1)))
# Sort by timestamp and extract characters
flag_chars.sort(key=lambda x: x[0])
flag = ''.join(c for _, c in flag_chars)
print("Flag:", flag)

---

Key Takeaways
Noise is intentional in misc challenges 2000 lines of debug logs exist solely to bury 21 meaningful ones. Always filter aggressively (grep INFO, grep ERROR) before reading manually.

Challenge Name: **Find the IP
Category: OSINT
Player Name : Kiran (unencrypted_striker_6121)
Challenge Solved Description:
A webcam screenshot of what appears to be a cable wakeboard park was provided. No GPS coordinates in the metadata this time the solution required visual recognition and reverse image searching to identify the live camera feed behind the image.

---

Step 1: Google Lens Reverse Image Search
Uploading the image to Google Lens and it **** immediately recognised the scene as a cable wakeboard park
One of the top results linked directly to a website
On viewing the full screen we getdirectly to a live video stream at:
http://78.186.26.188/camera/index.html#/video
Flag: BPCTF{78.186.26.188}
Key Takeaways
Always read watermarks. The text "Hip Notics Web Cam" was visible at the bottom of the image and was effectively the answer written on the challenge itself - easy to miss when focusing on metadata.

Challenge Name: **Find the IP
Category: OSINT
Player Name : Kiran (unencrypted_striker_6121)
Challenge Solved Description:
A forest photograph was provided. On the surface it looks like any dense woodland - no landmarks, no signs, no recognisable features. The entire solution lives inside the image's metadata, not the image itself.

---

Step 1: Running ExifTool
The first tool for any OSINT image challenge is always exiftool. It extracts every piece of metadata baked into the file:
$ exiftool IMG_20221118_0920.jpg     
ExifTool Version Number         : 13.25
File Name                       : IMG_20221118_0920.jpg
Directory                       : .
File Size                       : 260 kB
File Modification Date/Time     : 2026:02:14 20:02:47+05:30
File Access Date/Time           : 2026:02:14 20:03:03+05:30
File Inode Change Date/Time     : 2026:02:14 20:02:47+05:30
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Software                        : ImagePipeline v3.8.12
Modify Date                     : 2022:11:18 09:21:44
Artist                          : Unknown Photographer
Y Cb Cr Positioning             : Centered
Exposure Time                   : 1/125
F Number                        : 5.6
ISO                             : 200
Exif Version                    : 0232
Create Date                     : 2022:11:18 09:20:01
Components Configuration        : Y, Cb, Cr, -
Metering Mode                   : Center-weighted average
Focal Length                    : 35.0 mm
Color Space                     : Uncalibrated
White Balance                   : Auto
GPS Version ID                  : 2.3.0.0
GPS Latitude Ref                : South
GPS Longitude Ref               : East
XMP Toolkit                     : Image::ExifTool 13.50
Flash Fired                     : False
Flash Function                  : False
Flash Mode                      : Unknown
Flash Red Eye Mode              : False
Flash Return                    : No return detection
Image Width                     : 736
Image Height                    : 1106
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Aperture                        : 5.6
Image Size                      : 736x1106
Megapixels                      : 0.814
Shutter Speed                   : 1/125
GPS Latitude                    : 54 deg 25' 0.00" S
GPS Longitude                   : 3 deg 22' 0.00" E
Flash                           : No Flash
Focal Length                    : 35.0 mm
GPS Position                    : 54 deg 25' 0.00" S, 3 deg 22' 0.00" E
Light Value                     : 10.9
Most of the output is standard camera data - exposure, focal length, ISO. But two lines immediately stand out:
GPS Latitude   : 54 deg 25' 0.00" S
GPS Longitude  : 3 deg 22' 0.00" E
GPS Position   : 54 deg 25' 0.00" S, 3 deg 22' 0.00" E
The raw coordinates from exiftool: 54° 25' 0.00" S, 3° 22' 0.00" E
Converting to decimal degrees for easier searching:
Latitude:  -54.4167  (South = negative)
Longitude: +3.3667   (East = positive)
Now Pasting 54°25'S 3°22'E directly into Google Maps places the pin in the middle of the South Atlantic Ocean, far from any continent. Zooming out the coordinates on Google Maps reveals a tiny island at that exact position: Bouvet Island
Step 2: Constructing the Flag
The flag format combined the island name and its sovereign nation:
Flag: BPCTF{bouvet_island_norway}
Challenge Name: **The Trojan War
Category: Cryptography
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description:
This challenge was a chain puzzle solving each layer gave you what you needed to unlock the next. The theme was the Trojan War and Homer's Odyssey and the challenge description wasn't just flavour text it contained the actual password hints hidden in plain sight.
The chain looked like this:
AES.py → Google Drive URL → ZIP file → Flag.txt → ROT13 → Flag
                 ↑
           rsa.py gives you the ZIP password
Files provided:
AES.py →AES decryption script
rsa.py → RSA public key and ciphertext

---

Step 1: AES Decryption - Finding the Hidden URL
Drive:
https://drive.google.com/file/d/1BaxcxVDaPGCqRo9AFVh90AzaCE6hU42r/view
Step 2: RSA Cryptanalysis
Spotting the Weakness - Fermat's Factorization Attack
In secure RSA, the two prime factors p and q must be far apart from each other. If they are close together, an attack called Fermat's Factorization can break the key almost instantly.
To check if this is the case here, run:
from math import isqrt
n = 127865920957875327059505996767912960990196675444537077314411283942162182981335766093714137663028305326541856301703598005198772891427632782294580987389690424628053057426605280464917045369569623509368612585308461187913424796767527625719781829124644644581046192216323706744363001189716381140302705185878156970459
a = isqrt(n) + 1
while True:
    b2 = a*a - n
    b  = isqrt(b2)
    if b*b == b2:
        p = a - b
        q = a + b
        break
    a += 1
print(f"p - q = {abs(p-q)}")

Output: p - q = 9242

<aside> 💡
Why Does This Work?
Any number n = p × q can be rewritten as :n = a² − b²
</aside>
where a = (p+q)/2 and b = (p−q)/2. When p ≈ q, the value a is extremely close to √n, and b is tiny. So we just start from ⌈√n⌉ and count upward until we find a perfect square - which happens almost immediately when p and q are close
Decrypting the RSA Message
With p and q known, standard RSA decryption follows:
from math import isqrt
n = 127865920957875327059505996767912960990196675444537077314411283942162182981335766093714137663028305326541856301703598005198772891427632782294580987389690424628053057426605280464917045369569623509368612585308461187913424796767527625719781829124644644581046192216323706744363001189716381140302705185878156970459
e = 65537
c = 24885441848012775971684217685180315071153616389120044652942563794285730925141132334760627917279607107782065957587290077151211662309094636317416732303271933414956406197494080612002910414834403528383893773095397466117820296268244694924583168341285721216216715968127740616491140841070394832417137914703196886181
# Step 1: Factor n using Fermat
a = isqrt(n) + 1
while True:
    b2 = a*a - n
    b  = isqrt(b2)
    if b*b == b2:
        p, q = a - b, a + b
        break
    a += 1
# Step 2: Compute private key
phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)       # modular inverse
# Step 3: Decrypt
m   = pow(c, d, n)
plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(plaintext)

Output: b'Princess'

Step 3: Extracting the ZIP
What the Google Drive Contained
Visiting the URL recovered from the AES decryption opened a Google Drive folder. Inside was a single file: The_Odyssey.zip
Downloading and attempting to extract it immediately prompted for a password:
The ZIP contained one file Flag.txt that is protected with a password
Finding the Password
Rather than guessing blindly, the challenge had already handed us strong candidates throughout Steps 1 and 2:
The AES key was odysseus_journey - clearly Odyssey themed
The RSA plaintext returned Princess - a reference to Helen of Troy
The challenge description explicitly mentioned helen as "a treasure that carries a name"
The Google Drive folder itself was named The_Odyssey

Every single clue pointed to Greek mythology. Instead of trying passwords one by one manually, I wrote a small script that collected all the thematic keywords from the challenge and tried them automatically:
Step 4: ROT13 Decoding - The Final Step
Contents of Flag.txt
Opening the extracted Flag.txt revealed the flag was not in plaintext - it was encoded:
OCPGS{U3y3a_15_E3ge13i3q!!!}
Flag:BPCTF{H3l3n_15_R3tr13v3d!!!}
Key Takeaways:
Weak RSA primes lead to instant breaks. A difference of p − q = 9242 on a 1024-bit number is a critical mistake. Secure RSA requires |p − q| to be astronomically large.
Challenge Name: **Rolling Silence
Category: Cryptography
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description:
The binary's name says it all Rolling Silence. It takes input from nowhere, prints nothing, and exits quietly. No prompts, no output, no strings that make sense. The flag is never displayed it lives entirely inside the binary, encrypted in the .rodata section, waiting to be extracted through static analysis alone.

---

Step 1: Basic Reconnaissance
$ file rollingsilence
rollingsilence: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
Three things stand out statically linked (no external libraries), stripped (no debug symbols), and most importantly, running it produces absolutely nothing. No prompt, no output. Dead silence.
$ strings rollingsilence
    - b
.shstrtab
.text
.rodata
Virtually no readable strings. No flag, no "Enter flag", no "Wrong" or "Correct". This immediately tells us the flag is obfuscated or encrypted inside the binary and not stored as a plain string.
The only section names visible are .text (code) and .rodata (read-only data). Those are the two sections worth examining.
Step 2: Dumping the Sections
Using objdump to dump both sections raw:
26 bytes of scrambled data at address 0x402000. This is clearly not plaintext - but 26 bytes is a suspicious length. Flags typically follow a bpctf{...} format, and bpctf{ alone is 6 characters. This could be our encrypted flag.
Step 3: Disassembling the Code by Hand
Breaking the .text bytes into instructions:
401000: 48 31 ff           XOR   RDI, RDI          ; counter = 0
401003: b0 89              MOV   AL, 0x89           ; starting key = 0x89
401005: 48 83 ff 1a        CMP   RDI, 0x1a          ; compare counter with 26
401009: 7d 14              JGE   0x40101f            ; if counter >= 26, exit
40100b: 8a 9f 00 20 40 00  MOV   BL, [RDI+0x402000] ; load encrypted byte
401011: 30 c3              XOR   BL, AL              ; decrypt: byte XOR key
401013: 40 00 f8           ADD   AL, DIL             ; key += counter
401016: d0 c0              ROL   AL, 1               ; rotate key left by 1
401018: 34 a5              XOR   AL, 0xa5            ; key XOR 0xa5
40101a: 48 ff c7           INC   RDI                 ; counter++
40101d: eb e6              JMP   0x401005            ; loop back
40101f: b8 3c 00 00 00     MOV   EAX, 60             ; syscall: exit
401024: 31 ff              XOR   EDI, EDI             ; exit code = 0
401026: 0f 05              SYSCALL

---

Step 4: Understanding the Rolling Key
This is the critical insight. The key is not static - it mutates every iteration through three operations:
Initial key:  0x89
Each iteration:
  1. decrypt:  byte XOR key
  2. key = key + counter        (ADD AL, DIL)
  3. key = ROL(key, 1)          (rotate left 1 bit)
  4. key = key XOR 0xA5         (XOR with constant)
  5. counter++
This is called a rolling XOR cipher the key changes after every byte, making it impossible to break with a simple single-key XOR approach. That is what "Rolling" in the challenge name refers to.
Step 5: Simulating the Decryption in Python
Since the binary decrypts in registers and never prints, we simulate the exact same logic ourselves:
def rol8(val, count):
    """Rotate an 8-bit value left by count bits"""
    val &= 0xFF
    count &= 7
    return ((val << count) | (val >> (8 - count))) & 0xFF
# Encrypted bytes from .rodata at 0x402000
rodata = bytes.fromhex("ebc6a948bd61e98319c1b570de58b8498e2816f155a5092d2062")
key = 0x89        # starting key from: MOV AL, 0x89
decrypted = []
for i in range(len(rodata)):
    # Step 1: decrypt current byte
    dec_byte = rodata[i] ^ key
    decrypted.append(dec_byte)
    # Step 2: update key (mirroring the 3 instructions)
    key = (key + i) & 0xFF   # ADD AL, DIL
    key = rol8(key, 1)        # ROL AL, 1
    key = key ^ 0xA5          # XOR AL, 0xA5
print(bytes(decrypted).decode())

Output : bpctf{registers_are_state}

Flag:BPCTF{registers_are_state}
Key Takeaways
No output ≠ no flag. When a binary is completely silent, the logic is almost always in .rodata. Always dump both sections.

Challenge Name: **Biased Stream
Category: Cryptography
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description: Two files were provided - cipherstreamer.py containing a custom stream cipher implementation, and output.bin containing the encrypted flag.

---

Step 1: Understanding the Files
output.bin contains 28 bytes of binary data. Dumping it with objdump or Python:
$ python3 -c "import binascii; print(binascii.hexlify(open('output.bin','rb').read()).decode())"
Output : a606c9deccd1c8c3cbd9cfcef5d9ded8cfcbc7f5c6cfcbc1cbcdcfd7
cipherstreamer.py contains two components : a main() that just reads output.bin and prints its hex (no decryption). The cipher class A is the LFSR. The challenge is to understand its behaviour and reverse the encryption.
Step 2: Analysing the LFSR
The class A implements an 8-bit Linear Feedback Shift Register (LFSR) with:
Seed: 0x37
Feedback polynomial: 0xB8
Operation: shift left, XOR feedback if MSB was 1

Let's trace what it actually produces:
class A:
    def __init__(self):
        self.s = 0x37
    def g(self):
        t = self.s
        u = (t >> 7) & 1
        self.s = ((t << 1) ^ ((0xB8) & (-u))) & 255
        return self.s
lfsr = A()
for i in range(5):
    print(hex(lfsr.g()))

Output 0x6e # step 1: 0x37 << 1 = 0x6e, MSB of 0x37 = 0, no feedback 0xdc # step 2: 0x6e << 1 = 0xdc, MSB of 0x6e = 0, no feedback 0x00 # step 3: BUG - collapses to zero! 0x00 # stays zero forever 0x00

The LFSR is fatally broken. At step 3:
t = 0xdc → MSB = 1, so u = 1
In Python, u = -1 which in two's complement is 0xFFFFFFFF... (arbitrary precision)
0xB8 & (-1) = 0xB8
(0xdc << 1) & 0xFF = 0xb8
0xb8 ^ 0xb8 = 0x00 → dead state

This is the Python-specific bug: in C, -u on a uint8_t would be 0xFF (same result here), but the real issue is that 0xB8 happens to be an exact cancellation point for this particular state. After step 3, the entire keystream is zero meaning from byte 3 onwards, ciphertext equals plaintext (XOR with 0 is a no-op).
Step 3: Known Plaintext Attack
Since we know all CTF flags start with bpctf{, we can recover the keystream directly using known plaintext:
with open('output.bin', 'rb') as f:
    data = f.read()
flag_prefix = b'bpctf{'
# keystream[i] = ciphertext[i] XOR plaintext[i]
recovered_ks = [data[i] ^ flag_prefix[i] for i in range(len(flag_prefix))]
print([hex(k) for k in recovered_ks])
```Output
['0xc4', '0x76', '0xaa', '0xaa', '0xaa', '0xaa']
Two critical observations:
Keystream bytes 2–5 are all 0xaa the stream collapsed to a constant value rather than zero
The stream is completely biased once it collapses, every subsequent byte is identical and predictable

This is the biased stream leakage the challenge name points to. A proper LFSR would produce pseudorandom output. This one degenerates into a repeating constant after 2 bytes.
Step 4: Decrypting the Flag
With the keystream structure fully known [0xc4, 0x76, 0xaa, 0xaa, ...] - decryption is straightforward:
with open('output.bin', 'rb') as f:
    data = f.read()
# Keystream: first two bytes recovered via known plaintext,
# rest is constant 0xaa (the LFSR collapse value)
keystream = [0xc4, 0x76] + [0xaa] * (len(data) - 2)
flag = bytes([data[i] ^ keystream[i] for i in range(len(data))])
print(flag.decode())
Flag:BPCTF{biased_stream_leakage}
Challenge Name: **TheRustyFrame
Category: Binary Exploitation
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description: A stripped ELF binary written in Rust. No prompts, no obvious output when run directly. The challenge name is a hint rusty points to Rust and frame hints at stack frame manipulation. The binary hides both its expected input and its flag inside its logic.

---

Step 1: Basic Reconnaissance
$ file rusty_frame_S6NV0Zx
rusty_frame_S6NV0Zx: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, stripped
Running it:
$ ./rusty_frame_S6NV0Zx
$
Dead silence. No prompt, no output, no error.
Step 2: Strings Analysis
On using String i got some interest information
$ strings rusty_frame_S6NV0Zx  
...
src/main.rs         ← Rust source file reference
RUSTY_WIN           ← suspicious environment variable name
let_me_iH3          ← partial string: 'let_me_i' + assembly bytes
...
Step 3: Disassembly - Finding the Flag Check
Searching for instructions containing let_me_i in the binary:
data = open('rusty_frame_S6NV0Zx', 'rb').read()
idx = data.find(b'let_me_i')
print(hex(idx))
# Found at file offset 0xdedd
# Full instruction at 0xdedb:
# 48 b9 6c 65 74 5f 6d 65 5f 69 = movabs rcx, 'let_me_i'
The surrounding assembly decoded as:
0xded3:  movzx  eax, word [rsp+0xa8]      ; load 2 bytes from input on stack
0xdedb:  movabs rcx, 0x695f656d5f74656c   ; 'let_me_i' (little-endian)
0xdee5:  xor    rcx, [rsp+0xa0]           ; XOR with input[0:8]
0xdeed:  xor    rax, 0xa0e                ; mask check
0xdef3:  or     rax, rcx                  ; combine
0xdef6:  je     0xe42d                    ; jump to success if zero (all XOR = 0)
This is a classic XOR-based equality check:
Load 8 bytes of user input from the stack
XOR against let_me_i
If result is zero, the input matched they are equal and Jump to the success path

So the first 8 characters of the expected input are let_me_i. The next check continues the string  likely n to complete let_me_in.
Step 4: Testing the Password
With the discovered partial string:
$ echo "let_me_in" | ./rusty_frame_S6NV0Zx
bpctf{stand_proud_mate}
Also there are multiple ways an input can be feed ato get the flag
RUSTY_WIN appears in the binary's debug path strings (x.rs\x00RUSTY_WIN`) it's likely a leftover from development or a deliberately placed false lead.
Flag: BPCTF{stand_proud_mate}
Key Takeaways
XOR-based equality checks are transparent. A XOR B = 0 means A = B. When you see a value XOR with input and checked against zero, the value is  the expected input so no key recovery needed.
Challenge Name: **Phantom
Category: Miscellaneous
Player Name : Uddip Das (Evi1iXer)
Challenge Solved Description:
The key phrase here is "fix the engine" this isn't just flavour text. The binary is genuinely broken, and our job is to find out why and repair it.

---

Step 1: First Impressions
Before touching any disassembler, always run file on the binary to understand what you're working with.
$ file phantom
phantom: ELF 64-bit LSB executable, x86-64, statically linked, stripped
Low Hanging Fruit using Strings
Before loading anything into a disassembler, always run strings. It's fast and often reveals a lot:
Step 2: Locating the Flag in Memory
Using objdump to dump the .rodata section:
$ objdump -s -j .rodata phantom| grep -E "(bpctf|Wrong|Correct|Enter)"
Contents of section .rodata:
 4001e0 62706374 667b7068 616e746f 6d5f7275  bpctf{phantom_ru
 4002a4 456e7465 7220666c 61673a20 00        Enter flag:
 4002b1 57726f6e 672e0a00                    Wrong.
 4002b9 436f7272 65637421 0a00              Correct!
The string bpctf{phantom_ru sits at virtual address 0x4001e0
Step 4: Reconstructing the Flag - All Four Sections
Section A - First 16 Characters
At virtual address 0x100266e the disassembler reveals:
100266e:  vpxor  xmm0, xmm0, [rip-0x2496]   ; XOR input[0:16] with rodata
1002676:  vptest xmm0, xmm0                 ; test if result is zero
100267b:  jne    0x10029c6                  ; jump to Wrong if not zero
vpxor XORs 16 bytes of input against the 16 bytes at 0x4001e0. vptest checks if the result is all zeros  which only happens when input equals the key. Then jne sends mismatches to the "Wrong" path.
This confirms the first 16 characters: bpctf{phantom_ru
Section B - Next 8 Characters
At 0x1002681:
1002681:  movabs rcx, 0x6e74696d655f656e   ; load 'ntime_en'
100268b:  cmp    [rsp+0x28], rcx           ; compare with input[16:24]
1002690:  jne    0x10029c6                 ; Wrong if mismatch
The constant 0x6e74696d655f656e in memory order reads as ntime_en.
So it becomes: bpctf{phantom_runtime_en
Section C - Individual Byte Comparisons
Four cmpb instructions each check one byte:
1002696:  cmpb   $0x67, [rsp+0x30]   ; 'g'
100269b:  jne    0x10029c6
10026a1:  cmpb   $0x69, [rsp+0x31]   ; 'i'
10026a6:  jne    0x10029c6
10026ac:  cmpb   $0x6e, [rsp+0x32]   ; 'n'
10026b1:  jne    0x10029c6
10026bf:  cmpb   $0x65, [rsp+0x33]   ; 'e'
10026c4:  jne    0x10029c6
These add: gine
Running total: bpctf{phantom_runtime_engine
Section D - Closing Brace
At 0x10026b7:
10026b7:  cmp    al, 0x7d    ; compare with '}'  (0x7d = 125)
10026b9:  jne    0x10029c6
Final character: }
Assembled flag: bpctf{phantom_runtime_engine}
The Bug
The binary contains a flag verification routine, but there's a logic bug in the final comparison that causes it to always print "Wrong" even when the correct flag is provided.
Location: Virtual Address 0x10029c0, File Offset 0x19c1
Buggy Instruction:
10029c0:  0f 84 04 fd ff ff    je     0x10026ca
This instruction uses je (jump if equal) to jump to the "Correct!" message. However, the logic is inverted  it should use jne (jump if not equal) instead.
Flag: bpctf{phantom_runtime_engine}
Key Takeaways
One wrong bit breaks everything. The difference between 0x84 (je) and 0x85 (jne) is a single bit. In challenge binaries, always examine the final conditional jump i.e where intentional bugs are planted
