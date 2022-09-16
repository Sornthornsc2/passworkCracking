import hashlib
 
 
password_hexs = {
 'pw1':  '44afbc26b785d9c5cfce73aa06dd0711f2e290d5', #  sha1
 'pw2':  'd2e7560d96b0f6ceac88ac8d94f0fdc39d36252d2432ecb1ab510450a93b3c2c', #sha256
 'pw3':  '95d19ab48d18d4232b87bb086319998c',            # md5
 'spw1': '955597a308bd22402bf841f19d393526a15396cf49e9477af9f21f45fcfe13c8',
 'spw2': '00b961e20655b8cb16fb7aff3d3a28a3',
 'spw3': 'bbdefeaebc9ac07b9ad47fd8f9e1b7bf3170bcfc'
}
 
salt_hex = 'd41d8cd98f00b204e9800998ecf8427e'
salt_byte = bytearray.fromhex(salt_hex)
 
dict_textes = open('dic-0294.txt').readlines()
 
 
for line in dict_textes:
    password = line.strip()
 
    sha1hash   = hashlib.sha1(password.encode()).hexdigest() 
    if sha1hash == password_hexs['pw1']:
        print(f'found: pw1 => {password}')
 
    sha256hash = hashlib.sha256(password.encode()).hexdigest() 
    if sha256hash == password_hexs['pw2']:
        print(f'found: pw2 => {password}')
 
    md5hash    = hashlib.md5(password.encode()).hexdigest()
    if md5hash == password_hexs['pw3']:
        print(f'found: pw3 => {password}')
 
    # --- salted
 
    sha256 = hashlib.sha256()
    sha256.update(salt_byte)
    sha256.update(password.encode())
    sha256hash_salted = sha256.hexdigest()
    if sha256hash_salted == password_hexs['spw1']:
        print(f'found: spw1 => {password}')
 
    md5 = hashlib.md5()
    md5.update(salt_byte)
    md5.update(password.encode())
 
    md5hash_salted = md5.hexdigest()
    if md5hash_salted == password_hexs['spw2']:
        print(f'found: spw2 => {password}')
 
    sha1 = hashlib.sha1()
    sha1.update(salt_byte)
    sha1.update(password.encode())
    sha1hash_salted = sha1.hexdigest()
    if sha1hash_salted == password_hexs['spw3']:
        print(f'found: spw3 => {password}')
