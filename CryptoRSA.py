import sys
import asn1
from hashlib import sha256 
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

# Размер ключа 32 - AES256
key_bytes = 32 
# Нулевой вектор инициализации длиной 16 байт
iv = b'\x00' * AES.block_size
#iv = Random.new().read(AES.block_size)
# параметры криптосистемы
e = "d11b76d20128b2b3a7dfe6ad9185f3a4a382138725d92ae9753598b2d5a7f04df00449eae96d165af44b08cdb01add3d48dd"
d = "73a8f2880e85bbf94378e8d292b57c9a3293f39bb0ea136137c156fa2562c8727453d8889437c6a71095b2b66f00b54a50a71d0024df0a1295b281090da55cb8b42fe6a9038e77b523bc5cc51ef970f1452afbbe0ddbc732c0d01c899140cc64c21ec4f39d885cc47f3061141c3fa8bc76caba1d3dcba81ed4290779f6a2ba85" 
n = "c7d6067eccfdb99501fccb2e84c591d8ca2db03913960ce1354bbfca132043accddbd48376076cf4988a5738f941bdf039ef2c574e9f81b19fdaa382c8f9539922054dbb2d200e0718f840c90d8fed49b1bd4943505257fd6341a2fbf4c46f93561329826faa1d73b1b575163b45f7445f3c77be3ee6de5e79af9479194cb103"
# p = "c8c41024a5f894fbee76f23ec32d91f8b7097d3095fcb028646aafd094bc0ad11b76d20128b2b3a7dfe6ad9185f3a4a382138725d92ae9753598b2d5a7a8b969"
# q = "fed0795ca3c9d10f04df00449eae96d165af44b08cdb01add3d48dd479c5c457b2fbbffb4dcf8d656512623e70f060c22542ebff01d84db651b5e9e7b6323d8b"

def file_encryption(filepath):
    try:
        file = open(filepath)
    except FileNotFoundError as err:
        print(u'ERROR: Wrong file path')
    else:
        # Зашифрование файла алгоритмом AES-256 в режиме CBC   
        with open(filepath, "rb") as file:
            plaintext = file.read()
           # Генерируем случайный ключ 
        key = Random.new().read(key_bytes)
        assert len(key) == key_bytes
        # int.from_bytes - возвращает целое число, представленное данным массивом байт
        print(f"AES key: {hex(int.from_bytes(key, 'big'))[2:]}")
        # Создание нового шифра AES256-CBC  
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Шифрование, pad - дополнение неполного блока
        encrypttext = cipher.encrypt(pad(plaintext, AES.block_size))
        # RSA - зашифрование ключа key: key^e(mod n)
        # big - порядок байтов – MSB
        # в функции int() 16 - система счисления первого аргумента
        enkey = pow(int.from_bytes(key, 'big'), int(e, 16), int(n, 16))
    
        print("Open RSA key: e = ", e)
        print("Private RSA key: d = ", d)
        print("Module: n = ", n)
        
        # Преобразование в asn.1 формат
        asn1_text = asn_encoder(enkey, int(e, 16), int(n, 16), len(encrypttext), encrypttext, 'encrypt')
        
        with open("encrypted.txt", "wb") as file:
            file.write(asn1_text)

def file_decryption(filepath):
    try:
        file = open(filepath)
    except FileNotFoundError as err:
        print(u'ERROR: Wrong file path')
    else:
        parameters = []
        with open(filepath, "rb") as file:
            text = file.read()
        decoder = asn1.Decoder()
        # Начало декодирования
        decoder.start(text)
        asn_decoder(decoder, parameters)
        encrypttext = text[-parameters[-1]:]
        n = parameters[0]
        e = parameters[1]
        enkey = parameters[2]
        
        # RSA - дешифрование ключа key: key^d(mod n)
        key = pow(enkey, int(d, 16), n)
        # .to_bytes - возвращает массив байт, представляющий собой целое число
        key = key.to_bytes(key_bytes, "big")
        print(f"AES key: {hex(int.from_bytes(key, 'big'))[2:]}")
        print("Open RSA key: e = ", hex(e)[2:])
        print("Private RSA key: d = ", d)
        print("Module: n = ", hex(n)[2:])
    
        # Создание нового шифра AES256-CBC  
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Расшифрование шифртекста, unpad - убирает дополнение неполного блока
        decrypted = unpad(cipher.decrypt(encrypttext), AES.block_size)

        with open("decrypted.txt", "wb") as file:
            file.write(decrypted)
        
def signature_generation(filepath):
    try:
        file = open(filepath)
    except FileNotFoundError as err:
        print(u'ERROR: Wrong file path')
    else:
        with open(filepath, "rb") as file:
            message = file.read()
        # Вычисляем 256-битный (SHA-256) хэш-образ сообщения
        r = sha256(message).hexdigest()
        print ("SHA-256: r = ", r)
        # Зашифровываем число r на закрытом ключе: r^d(mod n)
        s = pow(int(r, 16), int(d, 16), int(n, 16))
        # закодировать в asn файл и вывести в текстовый файл
        
        # Преобразование в asn.1 формат
        asn1_text = asn_encoder(s, int(d, 16), int(n, 16), 0, 0, 'signature')
        
        with open("signature.txt", "wb") as file:
            file.write(asn1_text)


def signature_verification(filepath, signfile):
    try:
        file = open(filepath)
    except FileNotFoundError as err:
        print(u'ERROR: Wrong file path')
    try:
        file = open(signfile)
    except FileNotFoundError as err:
        print(u'ERROR: Wrong signature-file path')
    else:
        parameters = []
        with open(signfile, "rb") as file:
            text = file.read()
        decoder = asn1.Decoder()
        decoder.start(text)
        asn_decoder(decoder, parameters)
        n = parameters[0]
        s = parameters[2]
        # Расшифровываем подпись на открытом ключе: s^e(mod n)
        t = pow(s, int(e, 16), n)

        with open(filepath, "rb") as file:
            message = file.read()
        # Вычисляем хэш-образ сообщения
        r = sha256(message).hexdigest()

        # Сравниваем полученный хэш-образ сообщения и хэш из подписи
        if t == int(r, 16): 
            print (u'The signature is genuine.\n')
        else:
            print (u'ERROR: The signature is incorrect.\n')

def asn_encoder(data, e, n, lenth, encrypted, code):
    encoder = asn1.Encoder()
    # Начало кодирования
    encoder.start()
    # Основная последовательность
    encoder.enter(asn1.Numbers.Sequence)
    # Набор ключей RSA
    encoder.enter(asn1.Numbers.Set)
    # Последовательность -- первый ключ RSA
    encoder.enter(asn1.Numbers.Sequence)
        
    if code == 'encrypt':
        # Идентификатор RSA
        encoder.write(b'\x00\x01', asn1.Numbers.OctetString)
    elif code == 'signature':
        # Идентификатор подписи
        encoder.write(b'\x00\x40', asn1.Numbers.OctetString)
    else: 
        print ('error')
        exit(-1)
    # Необзяталеьный идентификатор ключа
    encoder.write(b'\x0C\x00', asn1.Numbers.UTF8String)

    # Последовательность, содержащая gараметры криптосистемы - n, e
    encoder.enter(asn1.Numbers.Sequence)  
    encoder.write(n, asn1.Numbers.Integer)
    encoder.write(e, asn1.Numbers.Integer)
    # Выход из последовательности открытого ключа
    encoder.leave() 
        
    # RSA зашифрованные данные 
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(data, asn1.Numbers.Integer)
    encoder.leave()
    
    # Выход из множества ключа RSA
    encoder.leave()
    # Выход из набора ключей
    encoder.leave() 
    
    if code == 'encrypt':
        # Последовательность данных зашифрованного сообщеняи
        encoder.enter(asn1.Numbers.Sequence)
        # Идентификатор алгоритма шифрования AES CBC
        encoder.write(b'\x10\x82', asn1.Numbers.OctetString)
        # Длина шифротекста
        encoder.write(lenth, asn1.Numbers.Integer)    
        # Запись шифртекста
        encoder.write(encrypted, asn1.Numbers.OctetString)
        # Выход из последовательности данных
        encoder.leave()
    
    # Выход из основной последовательности
    encoder.leave()  
    
    return encoder.output()

def asn_decoder(decoder, parameters):
    while not decoder.eof():
        try:
            tag = decoder.peek()
            if tag.nr == asn1.Numbers.Null:
                break
            if tag.typ == asn1.Types.Primitive:
                tag, value = decoder.read()
                # Если тип Integer
                if tag.nr == asn1.Numbers.Integer: 
                    # Добавляем значение в массив
                    parameters.append(value)
            else:
                decoder.enter()
                asn_decoder(decoder, parameters)
                decoder.leave()

        except asn1.Error:
            break

def main():
    if len(sys.argv) == 3 and sys.argv[1] == "-enc":
        print(u'\nFile encryption...\n')
        file_encryption(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "-dec":
        print(u'\nFile decryption...\n')
        file_decryption(sys.argv[2])        
    elif len(sys.argv) == 3 and sys.argv[1] == "-gen":
        print(u'\nd-signature generation...\n')
        signature_generation(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "-ver":
        print(u'\nd-signature verification...\n')
        signature_verification(sys.argv[2], sys.argv[3])
    else:
        print(u'\nusage: RSA_enc_dec.py <action> filepath [signfile]\n  <action>:\n\t-enc - encryption\n\t-dec - decryption\n\t-gen - d-signature generation\n\t-ver - d-signature verification\n  filepath - path to plain text\n  [signfile] - file name with the signature to verify')    

if __name__ == '__main__':
    main()