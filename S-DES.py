import tkinter as tk
import time
from concurrent.futures import ThreadPoolExecutor
# 初始置换IP
IP = [2, 6, 3, 1, 4, 8, 5, 7]
# 逆初始置换IP^-1
IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
# 扩展置换E
E = [4, 1, 2, 3, 2, 3, 4, 1]
# P盒置换P
P = [2, 4, 3, 1]
# S盒S0
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]
# S盒S1
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]
# 循环左移位数
SHIFT_AMOUNT = [1, 2]


def permute(data, permutation_table):
    """
    根据置换表对数据进行置换操作
    """
    return [data[i - 1] for i in permutation_table]


def left_shift(lst, shift_amount):
    """
    对列表进行循环左移操作
    """
    return lst[shift_amount:] + lst[:shift_amount]


def generate_keys(key):
    """
    生成S-DES的子密钥
    """
    key = permute(key, [3, 5, 2, 7, 4, 10, 1, 9, 8, 6])
    left_half = key[:5]
    right_half = key[5:]
    sub_keys = []
    for shift in SHIFT_AMOUNT:
        left_half = left_shift(left_half, shift)
        right_half = left_shift(right_half, shift)
        sub_key = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])
        sub_keys.append(sub_key)
    return sub_keys


def s_box_lookup(s_box, data):
    """
    在指定的S盒中进行查找替换操作
    """
    row = int(f"{data[0]}{data[-1]}", 2)
    col = int("".join(map(str, data[1:3])), 2)
    return bin(s_box[row][col])[2:].zfill(2)


def f_function(r_data, sub_key):
    """
    S-DES的轮函数F
    """
    expanded = permute(r_data, E)
    xored = [int(a) ^ int(b) for a, b in zip(expanded, sub_key)]
    left_half = xored[:4]
    right_half = xored[4:]
    s0_result = s_box_lookup(S0, left_half)
    s1_result = s_box_lookup(S1, right_half)
    combined = s_box_lookup(S0, left_half) + s_box_lookup(S1, right_half)
    return permute(list(map(int, combined)), P)


def sdes_encrypt(plaintext, key):
    """
    使用S-DES算法加密明文
    """
    sub_keys = generate_keys(key)
    permuted_plaintext = permute(plaintext, IP)
    left_half = permuted_plaintext[:4]
    right_half = permuted_plaintext[4:]
    for sub_key in sub_keys:
        f_result = f_function(right_half, sub_key)
        xored_left = [int(a) ^ int(b) for a, b in zip(left_half, f_result)]
        left_half = right_half
        right_half = xored_left
    ciphertext = permute(right_half + left_half, IP_INVERSE)
    return ciphertext


def sdes_decrypt(ciphertext, key):
    """
    使用S-DES算法解密密文
    """
    sub_keys = generate_keys(key)[::-1]
    permuted_ciphertext = permute(ciphertext, IP)
    left_half = permuted_ciphertext[:4]
    right_half = permuted_ciphertext[4:]
    for sub_key in sub_keys:
        f_result = f_function(right_half, sub_key)
        xored_left = [int(a) ^ int(b) for a, b in zip(left_half, f_result)]
        left_half = right_half
        right_half = xored_left
    plaintext = permute(right_half + left_half, IP_INVERSE)
    return plaintext


# GUI界面相关函数和设置
def encrypt_action():
    """
    加密按钮的点击事件处理函数
    """
    plaintext_str = plaintext_entry.get()
    key_str = key_entry.get()
    try:
        plaintext_bytes = bytes(plaintext_str, 'utf-8')
        key_bytes = bytes(key_str, 'utf-8')
        encrypted_result = []
        for i in range(0, len(plaintext_bytes)):
            plaintext = list(map(int, bin(plaintext_bytes[i])[2:].zfill(8)))
            key = list(map(int, bin(int.from_bytes(key_bytes, 'big'))[2:].zfill(10)))
            encrypted_text = sdes_encrypt(plaintext, key)
            encrypted_result.extend(encrypted_text)

        encrypted_result_str = "".join(map(str, encrypted_result))
        encrypted_text_box.delete(0, tk.END)
        encrypted_text_box.insert(0, encrypted_result_str)
    except:
        encrypted_text_box.delete(0, tk.END)
        encrypted_text_box.insert(0, "输入有误，请检查输入格式")


def decrypt_action():
    """
    解密按钮的点击事件处理函数
    """
    ciphertext_str = ciphertext_entry.get()
    key_str = key_entry.get()
    try:
        ciphertext_bytes = bytes(int(ciphertext_str, 2).to_bytes(len(ciphertext_str) // 8, 'big'))
        key_bytes = bytes(key_str, 'utf-8')
        decrypted_result = []
        for i in range(0, len(ciphertext_bytes)):
            ciphertext = list(map(int, bin(ciphertext_bytes[i])[2:].zfill(8)))
            key = list(map(int, bin(int.from_bytes(key_bytes, 'big'))[2:].zfill(10)))
            decrypted_text = sdes_decrypt(ciphertext, key)
            decrypted_result.extend(decrypted_text)

        decrypted_result_str = bytes(decrypted_result).decode('latin-1', errors='replace')
        decrypted_text_box.delete(0, tk.END)
        decrypted_text_box.insert(0, decrypted_result_str)
    except:
        decrypted_text_box.delete(0, tk.END)
        decrypted_text_box.insert(0, "输入有误，请检查输入格式")


def brute_force_action():
    """
    暴力破解按钮的点击事件处理函数
    """
    known_plaintext_str = known_plaintext_entry.get()
    known_ciphertext_str = known_ciphertext_entry.get()
    try:
        known_plaintext_bytes = bytes(known_plaintext_str, 'utf-8')
        known_ciphertext_bytes = bytes(int(known_ciphertext_str, 2).to_bytes(len(known_ciphertext_str) // 8, 'big'))

        start_time = time.time()

        def try_key(key_combination):
            binary_key = list(map(int, bin(key_combination)[2:].zfill(10)))
            for i in range(0, len(known_ciphertext_bytes)):
                ciphertext = list(map(int, bin(known_ciphertext_bytes[i])[2:].zfill(8)))
                decrypted_text = sdes_decrypt(ciphertext, binary_key)
                if decrypted_text == list(map(int, bin(known_plaintext_bytes[i])[2:].zfill(8))):
                    return binary_key

        with ThreadPoolExecutor() as executor:
            results = executor.map(try_key, range(2 ** 10))
            for result in results:
                if result:
                    end_time = time.time()
                    time_result = end_time - start_time
                    brute_force_result_text_box.delete(0, tk.END)
                    brute_force_result_text_box.insert(0, f"找到正确密钥: {result}，耗时: {time_result}秒")
                    break
    except:
        brute_force_result_text_box.delete(0, tk.END)
        brute_force_result_text_box.insert(0, "输入有误，请检查输入格式")


def key_uniqueness_action():
    """
    密钥唯一性测试按钮的点击事件处理函数
    """
    known_plaintext_str = known_plaintext_entry.get()
    known_ciphertext_str = known_ciphertext_entry.get()
    try:
        known_plaintext_bytes = bytes(known_plaintext_str, 'utf-8')
        known_ciphertext_bytes = bytes(int(known_ciphertext_str, 2).to_bytes(len(known_ciphertext_str) // 8, 'big'))

        found_keys = []
        for key_combination in range(2 ** 10):
            binary_key = list(map(int, bin(key_combination)[2:].zfill(10)))
            for i in range(0, len(known_ciphertext_bytes)):
                ciphertext = list(map(int, bin(known_ciphertext_bytes[i])[2:].zfill(8)))
                decrypted_text = sdes_decrypt(ciphertext, binary_key)
                if decrypted_text == list(map(int, bin(known_plaintext_bytes[i])[2:].zfill(8))):
                    found_keys.append(binary_key)

        if len(found_keys) > 1:
            key_uniqueness_result_text_box.delete(0, tk.END)
            key_uniqueness_result_text_box.insert(0, "存在不止一个密钥能对该明密文对进行正确加密解密")
        else:
            key_uniqueness_result_text_box.delete(0, tk.END)
            key_uniqueness_result_text_box.insert(0, "对于该明密文对，密钥是唯一的")

    except:
        key_uniqueness_result_text_box.delete(0, tk.END)
        key_uniqueness_result_text_box.insert(0, "输入有误，请检查输入格式")


root = tk.Tk()

# 输入明文
plaintext_label = tk.Label(root, text="输入明文（ASCII字符串）:")
plaintext_label.pack()
plaintext_entry = tk.Entry(root)
plaintext_entry.pack()

# 输入密钥
key_label = tk.Label(root, text="输入密钥（10位二进制字符串）:")
key_label.pack()
key_entry = tk.Entry(root)
key_entry.pack()

# 加密按钮
encrypt_button = tk.Button(root, text="加密", command=encrypt_action)
encrypt_button.pack()

# 显示加密结果
encrypted_label = tk.Label(root, text="加密结果（二进制表示）:")
encrypted_label.pack()
encrypted_text_box = tk.Entry(root)
encrypted_text_box.pack()

# 输入密文
ciphertext_label = tk.Label(root, text="输入密文（二进制字符串）:")
ciphertext_label.pack()
ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

# 解密按钮
decrypt_button = tk.Button(root, text="解密", command=decrypt_action)
decrypt_button.pack()

# 显示解密结果
decrypted_label = tk.Label(root, text="解密结果（ASCII字符串）:")
decrypted_label.pack()
decrypted_text_box = tk.Entry(root)
decrypted_text_box.pack()

# 输入已知明文（用于暴力破解和密钥唯一性测试）
known_plaintext_label = tk.Label(root, text="输入已知明文（ASCII字符串，用于暴力破解和密钥唯一性测试）:")
known_plaintext_label.pack()
known_plaintext_entry = tk.Entry(root)
known_plaintext_entry.pack()

# 输入已知密文（用于暴力破解和密钥唯一性测试）
known_ciphertext_label = tk.Label(root, text="输入已知密文（二进制字符串，用于暴力破解和密钥唯一性测试）:")
known_ciphertext_label.pack()
known_ciphertext_entry = tk.Entry(root)
known_ciphertext_entry.pack()

# 暴力破解按钮
brute_force_button = tk.Button(root, text="暴力破解", command=brute_force_action)
brute_force_button.pack()

# 显示暴力破解结果
brute_force_result_label = tk.Label(root, text="暴力破解结果:")
brute_force_result_label.pack()
brute_force_result_text_box = tk.Entry(root)
brute_force_result_text_box.pack()

# 密钥唯一性测试按钮
key_uniqueness_button = tk.Button(root, text="密钥唯一性测试", command=key_uniqueness_action)
key_uniqueness_button.pack()

# 显示密钥唯一性测试结果
key_uniqueness_result_label = tk.Label(root, text="密钥唯一性测试结果:")
key_uniqueness_result_label.pack()
key_uniqueness_result_text_box = tk.Entry(root)
key_uniqueness_result_text_box.pack()

root.mainloop()