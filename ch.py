# 导入 tkinter 模块用于创建图形界面
import tkinter as tk
from tkinter import filedialog, messagebox  # 用于文件选择对话框和消息弹窗
import hashlib  # 用于计算文件的哈希值
import os       # 用于文件路径和文件存在性检查

# 定义函数：计算指定文件的哈希值
def calculate_hash(file_path, algorithm='md5'):
    """
    根据指定的哈希算法（md5、sha1、sha256）计算文件的哈希值。
    参数:
        file_path (str): 文件路径
        algorithm (str): 哈希算法名称，默认使用 'md5'
    返回:
        str: 文件的哈希值（十六进制字符串），如果失败则返回 None
    """
    hash_func = None  # 初始化哈希函数对象

    # 根据用户选择的算法初始化对应的哈希函数
    if algorithm.lower() == 'md5':
        hash_func = hashlib.md5()
    elif algorithm.lower() == 'sha1':
        hash_func = hashlib.sha1()
    elif algorithm.lower() == 'sha256':
        hash_func = hashlib.sha256()
    else:
        # 如果算法不支持，抛出异常
        raise ValueError("Unsupported hash algorithm")

    try:
        # 以二进制方式读取文件内容，并分块更新哈希值
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):  # 每次读取 4096 字节
                hash_func.update(chunk)
        return hash_func.hexdigest()  # 返回最终的哈希值（十六进制字符串）
    except Exception as e:
        # 如果读取文件失败，弹出错误提示框
        messagebox.showerror("Error", f"Failed to read file:\n{e}")
        return None

# 定义函数：打开文件选择对话框并将选中的文件路径显示在输入框中
def browse_file():
    """
    弹出文件选择对话框，用户选择文件后将路径显示在输入框中。
    """
    file_path = filedialog.askopenfilename()  # 打开文件选择对话框
    if file_path:
        entry_file.delete(0, tk.END)          # 清空输入框内容
        entry_file.insert(0, file_path)       # 插入选中的文件路径

# 定义函数：执行哈希值计算并显示结果
def compute_hashes():
    """
    获取用户输入的文件路径，验证文件是否存在，
    然后计算并显示该文件的 MD5、SHA1 和 SHA256 哈希值。
    """
    file_path = entry_file.get()  # 获取输入框中的文件路径
    if not file_path or not os.path.isfile(file_path):
        # 如果路径为空或文件不存在，弹出警告提示框
        messagebox.showwarning("Warning", "Please select a valid file!")
        return

    # 分别计算三种哈希值
    md5_hash = calculate_hash(file_path, 'md5')
    sha1_hash = calculate_hash(file_path, 'sha1')
    sha256_hash = calculate_hash(file_path, 'sha256')

    # 清空文本框并显示计算结果
    text_result.delete('1.0', tk.END)
    text_result.insert(tk.END, f"File: {file_path}\n\n")
    text_result.insert(tk.END, f"MD5:    {md5_hash}\n")
    text_result.insert(tk.END, f"SHA1:   {sha1_hash}\n")
    text_result.insert(tk.END, f"SHA256: {sha256_hash}\n")

# 创建主窗口
root = tk.Tk()
root.title("文件哈希校验工具")      # 设置窗口标题
root.geometry("600x400")           # 设置窗口大小

# 顶部框架：包含文件路径输入框和“浏览”按钮
frame_top = tk.Frame(root)
frame_top.pack(pady=10, padx=10, fill=tk.X)

# 文件路径输入框
entry_file = tk.Entry(frame_top, width=50)
entry_file.pack(side=tk.LEFT, padx=(0,5), fill=tk.X, expand=True)

# “浏览”按钮：点击后打开文件选择对话框
btn_browse = tk.Button(frame_top, text="浏览...", command=browse_file)
btn_browse.pack(side=tk.LEFT)

# “计算哈希值”按钮：点击后执行哈希计算
btn_compute = tk.Button(root, text="计算哈希值", command=compute_hashes)
btn_compute.pack(pady=5)

# 文本框：用于显示计算结果
text_result = tk.Text(root, height=15)
text_result.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# 启动 GUI 主循环
root.mainloop()
