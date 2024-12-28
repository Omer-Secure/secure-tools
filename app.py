from flask import Flask, render_template, request, jsonify
import re
'''  '''
import hashlib
import os
import mimetypes
from zipfile import ZipFile
from PyPDF2 import PdfReader

app = Flask(__name__)

''' ------------------------------------------------------------------ '''
VALID_ASCII = "abcdefghijklmnopqrstuvwxyz0123456789.-"
HOMOGLYPH_MAP = {
    "ɑ": "a", "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "ѕ": "s", "υ": "u",
    "О": "O", "0": "O", "Ⅰ": "I", "ⅼ": "l",  # الحرف "l" اللاتيني لم يعد ضمن القائمة
    "Ꞓ": "C", "Ϲ": "C", "Ⅽ": "C",
    "с": "c", "о": "o", "р": "r", "а": "a", "е": "e", "і": "i", "ѕ": "s",
}

def is_homoglyph_spoof(input_text):
    """
    Detect if an email, domain, or URL contains homoglyph spoofing.
    """
    # Split the input into local and domain parts if it's an email
    if "@" in input_text:
        local_part, domain_part = input_text.split("@", 1)
        
        # Check the local part (before @)
        for char in local_part:
            if char in HOMOGLYPH_MAP or char.lower() not in VALID_ASCII:
                return True
        
        # Check the domain part (after @)
        for char in domain_part:
            if char in HOMOGLYPH_MAP or char.lower() not in VALID_ASCII:
                return True
    else:
        # Treat the input as a plain domain or URL
        for char in input_text:
            if char in HOMOGLYPH_MAP or char.lower() not in VALID_ASCII:
                return True

    return False

def validate_input(input_text):
    """
    Validate whether the input is an email address, a URL, or a plain domain.
    """
    # Check if the input is an email address
    if "@" in input_text:
        email_pattern = r"^[^@]+@([^\s@]+)$"
        if re.match(email_pattern, input_text):
            return input_text  # Return the full email address
        else:
            raise ValueError("Invalid email address format.")
    
    # Check if the input is a URL
    url_pattern = r"https?://([^\s/]+)"
    match = re.match(url_pattern, input_text)
    if match:
        return match.group(1)

    # Check for a plain domain
    domain_pattern = r"^[^\s@]+\.[a-zA-Z]{2,}$"
    if re.match(domain_pattern, input_text):
        return input_text

    raise ValueError("Invalid input format. Please provide a valid email, URL, or domain.")

@app.route('/homoglyph-spoofing-detector')
def homoglyph_spoofing_detector_page():
    return render_template('homoglyph-spoofing-detector.html')

@app.route('/check', methods=['POST'])
def check_homoglyph():
    data = request.json
    user_input = data.get("input", "")
    try:
        validated_input = validate_input(user_input)
        is_spoof = is_homoglyph_spoof(validated_input)
        return jsonify({"result": "spoof" if is_spoof else "safe"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
''' ------------------------------------------------------------------ '''


''' ------------------------------------------------------------------ '''
# VirusTotal API Key
API_KEY = os.environ.get("c6079ec6fba0024d60a180ca7ee9a19ca8a586c1367bc21fa842648582f90eaa", "")

# Functions for file analysis
def get_file_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            return file_hash.hexdigest()
    except Exception as e:
        return None

def check_pdf_for_phishing(file_path):
    try:
        reader = PdfReader(file_path)
        for page in reader.pages:
            content = page.extract_text()
            urls = re.findall(r"http[s]?://\S+", content)
            if urls:
                return True  # Found URLs
    except Exception:
        return False
    return False

@app.route("/file-analyzer")
def file_analyzer_page():
    return render_template("file-analyzer.html")

@app.route("/analyze-file", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]

    # Save the uploaded file temporarily
    file_path = os.path.join("uploads", file.filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(file_path)

    try:
        # Analyze file properties
        mime_type, _ = mimetypes.guess_type(file_path)
        file_hash = get_file_hash(file_path)
        is_phishing = check_pdf_for_phishing(file_path) if mime_type == "application/pdf" else False

        # Return analysis results
        return jsonify({
            "file_name": file.filename,
            "mime_type": mime_type,
            "file_hash": file_hash,
            "phishing_detected": is_phishing
        })
    finally:
        # Clean up temporary file
        if os.path.exists(file_path):
            os.remove(file_path)
''' ------------------------------------------------------------------ '''


''' ------------------------------------------------------------------ '''
# Encryption and Decryption Using caesar Cipher
def caesar_cipher(text, shift, encrypt = True):
    shift = shift if encrypt else -shift
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) %26 + start)
        else:
            result += char
    return result

# Encryption and Decryption Using Vigenere Cipher
def vigenere_cipher(text, key, encrypt = True):
    key = key.lower()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            shift = shift if encrypt else -shift
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
            key_index += 1
        else:
            result += char
    return result

# Encryption and Decryption Using Atbash Cipher
def atbash_cipher(text):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(ord('Z')- (ord(char)-ord('A')))
            else:
                result += chr(ord('z')- (ord(char)-ord('a')))
        else:
            result += char
    return result

# Encryption and Decryption using XOR Cipher
def xor_cipher(text, key):
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    return result

# Encryption and Decryption Using Rail-Fence Cipher
def rail_fence_cipher(text, key, encrypt = True):
    if encrypt:
        rail =[''] * key
        row = 0
        direction = 1
        for char in text:
            rail[row] += char
            if row == 0:
                direction = 1
            elif row == key - 1:
                direction = -1
            row += direction
        return ''.join(rail)
    else:
        rail = [''] * key
        idx = 0
        direction = 1
        length = [0] * key
        row = 0
        for char in text:
            length[row] += 1
            if row == 0:
                direction = 1
            elif row == key - 1:
                direction = -1
            row += direction
        for r in range(key):
            rail[r] = text[idx:idx + length[r]]
            idx += length(r)
        result = ""
        row = 0
        direction = 1
        for i in range(len(text)):
            result += rail[row][0]
            rail[row] = rail[row][1:]
            if row == 0:
                direction = 1
            elif row == key - 1:
                direction = -1
            row += direction
        return result

# Encryption and Decryption using Playfair Cipher
def playfair_cipher(text, key, encrypt = True):
    def generate_table(key):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        table = []
        used = set()
        for char in key.upper() +alphabet:
            if char not in used and char != 'J':
                table.append(char)
                used.add(char)
        return [table[i:i+5] for i in range(0, 25, 5)]

    def find_position(char, table):
        for i, row in enumerate(table):
            if char in row:
                return  i, row.index(char)
        return None, None

    def prepare_text(text):
        text = text.upper().replace("J", "I")
        prepared = ""
        i = 0
        while i < len(text):
            if i + 1 < len(text) and text[i] == text[i + 1]:
                prepared += text[i] + "X"
                i += 1
            else:
                prepared += text[i:i+2]
                i += 2
        if len(prepared) % 2 != 0:
            prepared += "X"
        return prepared

    table = generate_table(key)
    prepare_text = prepare_text(text)
    result = ""

    for i in range(0, len(prepare_text), 2):
        row1, col1 = find_position(prepare_text[i], table)
        row2, col2 = find_position(prepare_text[i + 1], table)
        if row1 == row2:
            if encrypt:
                result += table[row1][(col1 + 1) % 5] + table[row2][(col2 + 1) % 5]
            else:
                result += table[row1][(col1 - 1) % 5] + table[row2][(col2 - 1) % 5]
        elif col1 == col2:
            if encrypt:
                result += table[(row1 + 1) % 5][col1] + table[(row2 + 1) % 5][col2]
            else:
                result += table[(row1 - 1) % 5][col1] + table[(row2 - 1) % 5][col2]
        else:
            result += table[row1][col1] + table[row2][col2]
    return result

# Encryption and Decryption using Block Cipher
def block_cipher(text, key, encrypt = True):
    # The below program is Highly simplified version of DES, only for Education Purpose
    def permute(bits, permutation):
        return ''.join(bits[i] for i in permutation)

    def f_k(bits, key):
        return ''.join(str((int(b) ^ int(k)) & 1) for b, k in zip(bits, key))

    def des_round(text, key, encrypt = True):
        L, R = text[:4], text[4:]
        if encrypt:
            return R + f_k(L, key)
        else:
            return f_k(R, key) + L

    permutation = [1, 4, 2, 3, 6, 5, 0, 7] #example of Initial Permutation
    permuted_text = permute(text, permutation)
    round_key = key[:4]    #simplistic key scheduling
    if encrypt:
        return des_round(permuted_text, round_key)
    else:
        return des_round(permuted_text, round_key, encrypt=False)

@app.route('/encryption', methods=['POST'])
def encryption():
    try:
        data = request.json
        text = data['text']
        cipher = data['cipher']
        action = data.get('action', 'encrypt')
        key = data.get('key', None)
        encrypt = action == 'encrypt'
        
        if cipher == 'caesar':
            shift = int(key)
            result = caesar_cipher(text, shift, encrypt)
        elif cipher == 'vigenere':
            result = vigenere_cipher(text, key, encrypt)
        elif cipher == 'atbash':
            result = atbash_cipher(text)
        elif cipher == 'xor':
            result = xor_cipher(text, key)
        elif cipher == 'rail_fence':
            key = int(key)
            result = rail_fence_cipher(text, key, encrypt)
        elif cipher == 'playfair':
            result = playfair_cipher(text, key, encrypt)
        elif cipher == 'block':
            binary_text = ''.join(format(ord(c), '08b') for c in text)
            binary_key = ''.join(format(ord(c), '08b') for c in key)
            result = block_cipher(binary_text, binary_key, encrypt)
            result = ''.join(chr(int(result[i:i + 8], 2)) for i in range(0, len(result), 8))
        else:
            return jsonify({"error": "Invalid cipher method"}), 400

        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/encryption-tool')
def encryption_tool():
    return render_template('encryption-tool.html')
''' ------------------------------------------------------------------ '''


@app.route('/')
def homepage():
    return redirect('https://omer-secure.github.io/')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
