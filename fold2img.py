import os
import io
import glob
import json
import math
import random
import struct
import tarfile
import hashlib
import base64
import sys
import time
import argparse
import zlib
import psutil
import threading 
from datetime import datetime, timezone
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from reedsolo import RSCodec, ReedSolomonError
from PIL import Image, ImageDraw
from tqdm import tqdm
from functools import partial
import tempfile
import shutil
from collections import defaultdict

# 常量定义
MAGIC_NUMBER = b'F2I\x01'  # 文件标识魔数
PNG_END_MARKER = b'IEND\xaeB`\x82'  # PNG结束标记
DEFAULT_REDUNDANCY = 0.2  # 默认纠错冗余比例
MIN_CHUNK_SIZE = 1024  # 最小数据块大小 (1KB)
MAX_CHUNK_SIZE = 1024 * 1024  # 最大数据块大小 (1MB)
MAX_ECC_SYMBOLS = 250  # Reed-Solomon最大纠错符号数
DEFAULT_ECC_BLOCK_SIZE = 1024 * 1024 * 4  # 默认纠错处理块大小 (4MB)
MAX_WORKERS = os.cpu_count() * 2  # 最大并行工作数
MEMORY_LIMIT = psutil.virtual_memory().available * 0.7  # 内存使用上限

# 自定义异常体系
class Fold2ImgError(Exception):
    """基础异常类"""
    def __init__(self, message="Fold2Img系统错误", recovery_info=None, solution=""):
        self.message = message
        self.recovery_info = recovery_info or {}
        self.solution = solution or "请检查输入参数和系统资源"
        super().__init__(self.message)
    
    def __str__(self):
        return f"{self.message}\n解决方案: {self.solution}"

class EncryptionError(Fold2ImgError):
    """加密失败"""

class DecryptionError(Fold2ImgError):
    """解密失败"""

class IntegrityError(Fold2ImgError):
    """数据完整性校验失败"""

class CarrierError(Fold2ImgError):
    """载体图片问题"""

class RecoveryError(Fold2ImgError):
    """数据恢复失败"""

class MemoryError(Fold2ImgError):
    """内存不足"""

# 资源监控装饰器
def monitor_resources(func):
    """带阈值检查的资源监控"""
    def wrapper(*args, **kwargs):
        process = psutil.Process()
        start_mem = process.memory_info().rss
        start_time = time.time()
        mem_peak = start_mem
        last_check = time.time()
        
        # 内存检查函数
        def check_memory():
            nonlocal mem_peak, last_check
            current_time = time.time()
            # 每0.5秒检查一次内存
            if current_time - last_check > 0.5:
                current_mem = process.memory_info().rss
                mem_peak = max(mem_peak, current_mem)
                if current_mem > MEMORY_LIMIT:
                    raise MemoryError(f"内存使用超过安全阈值: {current_mem/(1024*1024):.2f}MB > {MEMORY_LIMIT/(1024*1024):.2f}MB")
                last_check = current_time
        
        # 注入内存检查到函数中
        if hasattr(func, '_monitored'):
            result = func(*args, **kwargs)
        else:
            func._monitored = True
            try:
                # 创建检查线程
                stop_event = threading.Event()
                def monitor_thread():
                    while not stop_event.is_set():
                        check_memory()
                        time.sleep(0.1)
                
                monitor = threading.Thread(target=monitor_thread, daemon=True)
                monitor.start()
                
                result = func(*args, **kwargs)
            finally:
                stop_event.set()
                monitor.join(timeout=1.0)
                del func._monitored
        
        end_time = time.time()
        end_mem = process.memory_info().rss
        elapsed = end_time - start_time
        mem_used = (mem_peak - start_mem) / (1024 * 1024)
        
        if VERBOSE:
            print(f"{func.__name__} 完成, 耗时: {elapsed:.2f}s, 峰值内存: {mem_used:.2f}MB")
        return result
    return wrapper

# 压缩与加密模块
@monitor_resources
@monitor_resources
def compress_folder(source_folder: str) -> bytes:
    """流式压缩文件夹，减少内存占用"""
    buffer = io.BytesIO()
    try:
        with tarfile.open(fileobj=buffer, mode='w:xz') as tar:
            # 递归添加文件，避免一次性加载
            for root, dirs, files in os.walk(source_folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=source_folder)
                    tar.add(full_path, arcname=arcname)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        raise Fold2ImgError(f"压缩文件夹失败: {str(e)}") from e


def dynamic_iterations():
    """根据系统性能动态计算迭代次数"""
    base = 100000
    try:
        # 简单性能测试
        start = time.time()
        hashlib.pbkdf2_hmac('sha256', b'test', b'salt', 1000, 32)
        duration = time.time() - start
        
        # 根据内存情况调整
        mem_factor = min(1.0, psutil.virtual_memory().available / (1024 * 1024 * 500))
        return max(base, min(int(base * (0.5 / duration) * mem_factor), 500000))
    except:
        return base

@monitor_resources
def encrypt_data(data: bytes, password: str) -> tuple:
    """流式加密数据，使用生成器减少内存占用"""
    try:
        salt = get_random_bytes(32)
        iv = get_random_bytes(12)
        
        # PBKDF2密钥派生
        iterations = dynamic_iterations()
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt, 
            iterations, 
            32
        )
        
        # 使用流式加密
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        encrypted_chunks = []
        
        # 动态调整块大小基于可用内存
        chunk_size = min(1024 * 1024 * 4, max(MIN_CHUNK_SIZE, int(MEMORY_LIMIT * 0.1)))
        total_size = len(data)
        
        for i in tqdm(range(0, total_size, chunk_size), desc="加密数据", unit="B", unit_scale=True):
            chunk = data[i:i+chunk_size]
            encrypted_chunks.append(cipher.encrypt(chunk))
        
        tag = cipher.digest()
        return salt, iv, tag, b''.join(encrypted_chunks), iterations
    except Exception as e:
        raise EncryptionError(f"加密失败: {str(e)}") from e

def create_metadata(source_folder: str, salt: bytes, iv: bytes, 
                   tag: bytes, encrypted_data: bytes, chunk_size: int, 
                   iterations: int, ecc_nsym: int, ecc_block_size: int) -> dict:
    """创建包含完整恢复信息的元数据"""
    return {
        "version": "2.0",
        "folder_name": os.path.basename(source_folder),
        "original_path": os.path.abspath(source_folder),
        "compression": "tar.xz",
        "encryption": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "hash": hashlib.sha256(encrypted_data).hexdigest(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "original_size": len(encrypted_data),
        "redundancy": DEFAULT_REDUNDANCY,
        "chunk_size": chunk_size,
        "iterations": iterations,
        "ecc_nsym": ecc_nsym,
        "ecc_block_size": ecc_block_size,
        "total_chunks": 0  # 将在分割后更新
    }

# 纠错与数据分割模块
@monitor_resources
def add_error_correction(data: bytes, redundancy: float = DEFAULT_REDUNDANCY) -> tuple:
    """并行添加Reed-Solomon纠错码"""
    try:
        data_size = len(data)
        available_mem = psutil.virtual_memory().available
        
        # 动态调整块大小
        ecc_block_size = min(DEFAULT_ECC_BLOCK_SIZE, max(MIN_CHUNK_SIZE, int(available_mem * 0.2)))
        
        # 根据数据大小自动调整块大小
        if data_size > 100 * 1024 * 1024:  # >100MB
            ecc_block_size = max(ecc_block_size, 4 * 1024 * 1024)  # 4MB块
            
        nsym = min(MAX_ECC_SYMBOLS, int(ecc_block_size * redundancy))
        nsym = max(nsym, 10)
        
        total_blocks = (data_size + ecc_block_size - 1) // ecc_block_size
        print(f"添加纠错码: {total_blocks} 个块, 每块 {ecc_block_size//1024}KB, 纠错符号数: {nsym}")
        
        #  智能块大小调整
        MAX_BLOCKS = 1000  # 最大块数限制
        if total_blocks > MAX_BLOCKS:
            # 调整块大小以减少块数量
            ecc_block_size = min(
                MAX_ECC_BLOCK_SIZE,
                max(ecc_block_size, data_size // MAX_BLOCKS)
            )
            total_blocks = (data_size + ecc_block_size - 1) // ecc_block_size
            nsym = min(MAX_ECC_SYMBOLS, int(ecc_block_size * redundancy))
            print(f"调整块大小至 {ecc_block_size//1024}KB, 新块数: {total_blocks}")
            
        # 使用更高效的并行处理
        rs = RSCodec(nsym)
        encoded_data = bytearray(len(data) + total_blocks * nsym)
        
        # 动态计算并行度
        max_workers = min(os.cpu_count(), 8, max(4, total_blocks // 10))
        
        # 使用更高效的并行处理模型
        def process_block(args):
            idx, start_idx = args
            end_idx = min(start_idx + ecc_block_size, data_size)
            block = data[start_idx:end_idx]
            if len(block) < ecc_block_size:
                block += b'\0' * (ecc_block_size - len(block))
            return idx, rs.encode(block)
        
        # 使用线程池提高小任务效率
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for idx, start_idx in enumerate(range(0, data_size, ecc_block_size)):
                futures.append(executor.submit(process_block, (idx, start_idx)))
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="添加纠错码"):
                idx, encoded_block = future.result()
                start_pos = idx * (ecc_block_size + nsym)
                encoded_data[start_pos:start_pos + len(encoded_block)] = encoded_block
        
        return bytes(encoded_data), nsym, ecc_block_size
    except Exception as e:
        raise RecoveryError(f"添加纠错码失败: {str(e)}") from e

def calculate_chunk_size(image_files: list) -> int:
    """基于载体图片计算最佳数据块大小"""
    if not image_files:
        return MAX_CHUNK_SIZE
        
    try:
        # 计算安全嵌入空间（保留4KB元数据空间）
        sizes = []
        for img in image_files:
            try:
                size = os.path.getsize(img)
                if size > 4096:  # 忽略过小的文件
                    sizes.append(size)
            except OSError:
                continue
        
        if not sizes:
            return MAX_CHUNK_SIZE
            
        min_size = min(sizes) - 4096
        return max(MIN_CHUNK_SIZE, min(min_size, MAX_CHUNK_SIZE))
    except Exception as e:
        print(f"计算块大小出错，使用默认值: {str(e)}")
        return MAX_CHUNK_SIZE

def split_data(data: bytes, chunk_size: int) -> list:
    """分割数据为等长块"""
    try:
        total_chunks = (len(data) + chunk_size - 1) // chunk_size
        print(f"分割数据: {len(data)//(1024*1024)} MB -> {total_chunks} 个块, 每块 {chunk_size//1024} KB")
        
        chunks = []
        pbar = tqdm(total=len(data), desc="分割数据", unit="B", unit_scale=True)
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            # 填充最后一块
            if len(chunk) < chunk_size:
                chunk += b'\0' * (chunk_size - len(chunk))
            chunks.append(chunk)
            pbar.update(len(chunk))
        
        pbar.close()
        return chunks
    except Exception as e:
        raise Fold2ImgError(f"数据分割失败: {str(e)}") from e

# 图片载体处理模块
def validate_images(image_files: list, required_size: int) -> list:
    """验证图片载体是否符合要求"""
    valid_images = []
    supported_formats = ('.png', '.bmp', '.jpg', '.jpeg', '.webp', '.avif')
    
    for img_path in image_files:
        if img_path.lower().endswith(supported_formats):
            try:
                if os.path.getsize(img_path) >= required_size:
                    # 验证是否为有效图片
                    try:
                        with Image.open(img_path) as img:
                            img.verify()
                        valid_images.append(img_path)
                    except Exception:
                        print(f"跳过无效图片: {img_path}")
                        continue
            except OSError:
                continue
    return valid_images

def generate_carrier_images(num_images: int, min_size: int, output_folder: str) -> list:
    """生成优化大小的载体图片"""
    try:
        os.makedirs(output_folder, exist_ok=True)
        generated_images = []
        
        # 动态计算图片尺寸
        img_size = max(512, int(math.sqrt(min_size * 2.5)))  # 调整尺寸计算
        
        print(f"生成 {num_images} 张载体图片, 尺寸: {img_size}x{img_size} 像素")
        
        for i in tqdm(range(num_images), desc="生成载体图片"):
            # 使用更高效的图像生成方法
            img = Image.new('RGB', (img_size, img_size), color=(
                random.randint(100, 200),
                random.randint(100, 200),
                random.randint(100, 200)
            ))
            
            draw = ImageDraw.Draw(img)
            
            # 添加少量随机元素
            for _ in range(5):
                x, y = random.randint(0, img_size), random.randint(0, img_size)
                radius = random.randint(10, 50)
                color = (
                    random.randint(0, 255),
                    random.randint(0, 255),
                    random.randint(0, 255)
                )
                draw.ellipse([x, y, x+radius, y+radius], fill=color)
            
            # 使用更高效的JPEG格式
            img_path = os.path.join(output_folder, f"carrier_{i:04d}.jpg")
            img.save(img_path, format='JPEG', quality=85)
            generated_images.append(img_path)
        
        return generated_images
    except Exception as e:
        raise CarrierError(f"生成载体图片失败: {str(e)}") from e

# 安全写入图片模块
def write_data_to_image(image_path: str, chunk_index: int, 
                      chunk_data: bytes, output_folder: str) -> str:
    """将数据块安全嵌入图片文件"""
    try:
        # 流式读取图片
        with open(image_path, 'rb') as f:
            img_data = f.read()
        
        # 定位文件尾（兼容不同格式）
        if img_data.endswith(PNG_END_MARKER):
            end_pos = img_data.rfind(PNG_END_MARKER) + len(PNG_END_MARKER)
        else:
            # 尝试查找其他格式的结束标记
            if b'\xff\xd9' in img_data:  # JPEG
                end_pos = img_data.rfind(b'\xff\xd9') + 2
            elif b'WEBP' in img_data:  # WebP
                end_pos = len(img_data)
            else:
                end_pos = len(img_data)  # 默认追加到文件末尾
        
        # 构建嵌入数据结构
        payload = (
            MAGIC_NUMBER +
            struct.pack('>I', chunk_index) +  # 大端序块索引
            struct.pack('>I', len(chunk_data)) +  # 数据长度
            chunk_data
        )
        
        # 创建新图片文件
        new_img_data = img_data[:end_pos] + payload
        filename = f"secured_{os.path.basename(image_path)}"
        output_path = os.path.join(output_folder, filename)
        
        with open(output_path, 'wb') as f:
            f.write(new_img_data)
        
        return output_path
    except Exception as e:
        file_size = os.path.getsize(image_path) if os.path.exists(image_path) else 0
        raise CarrierError(
            f"写入图片失败: {str(e)}", 
            recovery_info={
                "image": image_path,
                "size": file_size,
                "chunk_index": chunk_index,
                "chunk_size": len(chunk_data)
            },
            solution="尝试使用其他图片格式或更大尺寸的图片"
        ) from e

# 提取与恢复模块
def extract_payload(image_path: str) -> tuple:
    """从图片中提取有效载荷"""
    try:
        with open(image_path, 'rb') as f:
            data = f.read()
        
        # 查找有效载荷
        marker_pos = data.rfind(MAGIC_NUMBER)
        if marker_pos == -1:
            return None, None, None
        
        header = data[marker_pos:marker_pos+12]
        chunk_index = struct.unpack('>I', header[4:8])[0]
        data_length = struct.unpack('>I', header[8:12])[0]
        
        payload_start = marker_pos + 12
        payload_end = payload_start + data_length
        chunk_data = data[payload_start:payload_end]
        
        return chunk_index, data_length, chunk_data
    except Exception as e:
        raise RecoveryError(f"提取有效载荷失败: {str(e)}") from e

@monitor_resources
def reconstruct_data(image_folder: str, password: str, output_folder: str) -> str:
    """使用磁盘缓存重建数据，减少内存占用"""
    try:
        # 使用临时文件处理大数据
        with tempfile.TemporaryDirectory() as temp_dir:
            # 收集所有安全图片
            image_files = glob.glob(os.path.join(image_folder, 'secured_*'))
            if not image_files:
                raise ValueError("未找到安全图片文件")
            
            # 并行提取数据块
            chunks = {}
            missing_chunks = set()
            print(f"从 {len(image_files)} 张图片中提取数据...")
            
            with ThreadPoolExecutor(max_workers=min(8, os.cpu_count())) as executor:
                futures = {executor.submit(extract_payload, img): img for img in image_files}
                
                for future in tqdm(as_completed(futures), total=len(futures), desc="提取图片数据"):
                    img_path = futures[future]
                    try:
                        chunk_index, _, chunk_data = future.result()
                        if chunk_index is not None:
                            chunks[chunk_index] = chunk_data
                    except Exception as e:
                        print(f"警告: 提取 {os.path.basename(img_path)} 失败: {str(e)}")
            
            # 检查元数据块
            if 0 not in chunks:
                raise RecoveryError("缺失元数据块，无法恢复", {
                    "found_chunks": list(chunks.keys())
                })
            
            # 解析元数据
            metadata_json = chunks[0].rstrip(b'\0').decode('utf-8')
            metadata = json.loads(metadata_json)
            total_chunks = metadata['total_chunks']
            chunk_size = metadata['chunk_size']
            ecc_nsym = metadata.get('ecc_nsym', min(MAX_ECC_SYMBOLS, int(DEFAULT_ECC_BLOCK_SIZE * metadata.get('redundancy', DEFAULT_REDUNDANCY))))
            ecc_block_size = metadata.get('ecc_block_size', DEFAULT_ECC_BLOCK_SIZE)
            
            # 创建临时文件存储重建数据
            temp_data_path = os.path.join(temp_dir, "combined_data.bin")
            with open(temp_data_path, 'wb') as f:
                # 写入数据块
                for i in tqdm(range(1, total_chunks), desc="合并数据块"):
                    if i in chunks:
                        f.write(chunks[i])
                    else:
                        f.write(b'\0' * chunk_size)
                        missing_chunks.add(i)
            
            # 计算纠错块大小
            ecc_block_total_size = ecc_block_size + ecc_nsym
            file_size = os.path.getsize(temp_data_path)
            
            # 移除纠错码
            # 使用内存映射处理大文件
            corrected_data_path = os.path.join(temp_dir, "corrected_data.bin")
            
            # 创建目标文件并设置大小
            with open(corrected_data_path, 'wb') as f:
                f.truncate(metadata['original_size'])
            
            # 使用内存映射提高大文件处理性能
            with open(temp_data_path, 'rb') as f_in, \
                 open(corrected_data_path, 'r+b') as f_out:
                
                # 内存映射输入输出文件
                mmap_in = mmap.mmap(f_in.fileno(), 0, access=mmap.ACCESS_READ)
                mmap_out = mmap.mmap(f_out.fileno(), 0, access=mmap.ACCESS_WRITE)
                
                rs = RSCodec(ecc_nsym)
                ecc_block_total_size = ecc_block_size + ecc_nsym
                
                # 并行解码
                def decode_block(idx):
                    start_pos = idx * ecc_block_total_size
                    end_pos = start_pos + ecc_block_total_size
                    if end_pos > len(mmap_in):
                        return
                    
                    block = mmap_in[start_pos:end_pos]
                    try:
                        decoded = rs.decode(block)[0]
                    except ReedSolomonError:
                        decoded = block[:ecc_block_size]  # 使用原始数据
                        #f_out.write(decoded)
                        print(f"块 {pos//ecc_block_total_size} 纠错失败，使用原始数据")
                    
                    # 直接写入内存映射位置
                    output_start = idx * ecc_block_size
                    output_end = output_start + ecc_block_size
                    if output_end > len(mmap_out):
                        output_end = len(mmap_out)
                    mmap_out[output_start:output_end] = decoded[:output_end-output_start]
                
                # 并行处理块
                total_blocks = (len(mmap_in) + ecc_block_total_size - 1) // ecc_block_total_size
                with ThreadPoolExecutor(max_workers=min(8, os.cpu_count())) as executor:
                    list(tqdm(executor.map(decode_block, range(total_blocks)), 
                             total=total_blocks, desc="移除纠错码"))
                
                # 确保刷新写入
                mmap_out.flush()
            
            # 截断到原始大小
            corrected_size = os.path.getsize(corrected_data_path)
            if corrected_size > metadata['original_size']:
                with open(corrected_data_path, 'r+b') as f:
                    f.truncate(metadata['original_size'])
            
            # 解密数据
            salt = base64.b64decode(metadata['salt'])
            iv = base64.b64decode(metadata['iv'])
            tag = base64.b64decode(metadata['tag'])
            
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 
                                     metadata['iterations'], 32)
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            
            decrypted_path = os.path.join(temp_dir, "decrypted.tar.xz")
            with open(corrected_data_path, 'rb') as f_in, open(decrypted_path, 'wb') as f_out:
                # 分块解密
                chunk_size = 1024 * 1024 * 4  # 4MB
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(cipher.decrypt(chunk))
                
                # 验证标签
                try:
                    cipher.verify(tag)
                except ValueError as e:
                    raise DecryptionError(f"解密验证失败: {str(e)}") from e
            
            # 解压恢复文件夹
            output_path = os.path.join(output_folder, metadata['folder_name'])
            os.makedirs(output_path, exist_ok=True)
            
            with tarfile.open(decrypted_path, 'r:xz') as tar:
                tar.extractall(path=output_path)
            
            return output_path
    except Exception as e:
        raise RecoveryError(f"恢复数据失败: {str(e)}") from e

# 工作流程实现
@monitor_resources
def encode_folder(source_folder: str, image_folder: str, 
                password: str, output_folder: str, redundancy: float = DEFAULT_REDUNDANCY) -> list:
    """主编码流程"""
    try:
        # 0. 验证输入
        if not os.path.isdir(source_folder):
            raise Fold2ImgError(f"源文件夹不存在: {source_folder}")
        
        # 检查内存
        if psutil.virtual_memory().available < 1024 * 1024 * 100:  # 小于100MB
            raise MemoryError("可用内存不足，操作取消")
        
        # 1. 压缩文件夹
        print("压缩文件夹中...")
        compressed_data = compress_folder(source_folder)
        print(f"压缩完成，大小: {len(compressed_data)//(1024*1024)} MB")
        
        # 2. 加密数据
        print("加密数据中...")
        salt, iv, tag, encrypted_data, iterations = encrypt_data(compressed_data, password)
        print(f"加密完成，大小: {len(encrypted_data)//(1024*1024)} MB")
        
        # 3. 准备图片载体
        image_files = glob.glob(os.path.join(image_folder, '*'))
        chunk_size = calculate_chunk_size(image_files)
        print(f"计算块大小: {chunk_size//1024} KB")
        
        # 4. 添加纠错码
        print("添加纠错码...")
        start_time = time.time()
        data_with_ecc, ecc_nsym, ecc_block_size = add_error_correction(encrypted_data, redundancy)
        ecc_time = time.time() - start_time
        print(f"纠错完成, 耗时: {ecc_time:.1f}秒, 数据大小: {len(data_with_ecc)//(1024*1024)} MB (冗余: {redundancy*100:.1f}%, 纠错符号数: {ecc_nsym})")
        
        # 5. 创建元数据
        metadata = create_metadata(source_folder, salt, iv, tag, 
                                  encrypted_data, chunk_size, iterations, ecc_nsym, ecc_block_size)
        
        # 6. 分割数据
        chunks = split_data(data_with_ecc, chunk_size)
        total_chunks = len(chunks) + 1  # 包括元数据块
        metadata['total_chunks'] = total_chunks
        
        # 7. 创建元数据块
        metadata_json = json.dumps(metadata)
        metadata_chunk = metadata_json.encode() 
        # 填充到块大小
        if len(metadata_chunk) < chunk_size:
            metadata_chunk += b'\0' * (chunk_size - len(metadata_chunk))
        all_chunks = [metadata_chunk] + chunks
        
        # 8. 提示用户所需图片数量
        print(f"\n需要 {total_chunks} 张图片来存储数据")
        print(f"在 '{image_folder}' 中找到 {len(image_files)} 张可用图片")
        
        # 9. 确保足够载体图片
        if len(image_files) < total_chunks:
            needed = total_chunks - len(image_files)
            print(f"需要额外 {needed} 张载体图片，将在 '{output_folder}' 中生成...")
            new_images = generate_carrier_images(needed, chunk_size + 4096, output_folder)
            image_files.extend(new_images)
            print(f"已生成 {len(new_images)} 张新图片")
        else:
            # 如果图片多于需要，只使用所需数量
            image_files = image_files[:total_chunks]
            print(f"将使用前 {total_chunks} 张图片")
        
        # 10. 确保输出目录存在
        os.makedirs(output_folder, exist_ok=True)
        
        # 11. 并行写入图片（使用进程池）
        secured_images = []
        print(f"\n将数据嵌入到 {len(all_chunks)} 张图片中...")
        
        # 使用进程池处理CPU密集型任务
        with ProcessPoolExecutor(max_workers=min(8, os.cpu_count())) as executor:
            # 使用偏函数固定参数
            worker = partial(write_data_to_image, output_folder=output_folder)
            futures = []
            
            for i, img_path in enumerate(image_files):
                futures.append(executor.submit(worker, img_path, i, all_chunks[i]))
            
            # 使用进度条显示写入进度
            for future in tqdm(as_completed(futures), total=len(futures), desc="嵌入图片"):
                try:
                    result = future.result()
                    secured_images.append(result)
                except Exception as e:
                    print(f"图片嵌入失败: {str(e)}")
        
        return secured_images
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise Fold2ImgError(f"编码过程失败: {str(e)}") from e

def decode_images(image_folder: str, password: str, output_folder: str) -> str:
    """主解码流程"""
    # 1. 重建数据
    restored_folder = reconstruct_data(image_folder, password, output_folder)
    
    # 2. 验证恢复结果
    if not os.path.isdir(restored_folder):
        raise Fold2ImgError(f"文件夹恢复失败: {restored_folder}")
    
    return restored_folder

# CLI接口实现
def main():
    global VERBOSE  # 添加全局变量
    
    parser = argparse.ArgumentParser(
        description='Fold2Img - 将文件夹安全嵌入图片',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # 编码命令
    encode_parser = subparsers.add_parser('encode', help='编码文件夹到图片')
    encode_parser.add_argument('-s', '--source', required=True, help='源文件夹路径')
    encode_parser.add_argument('-i', '--images', required=True, help='载体图片目录')
    encode_parser.add_argument('-p', '--password', required=True, help='加密密码')
    encode_parser.add_argument('-o', '--output', default='secured_images', help='输出目录')
    encode_parser.add_argument('-r', '--redundancy', type=float, default=DEFAULT_REDUNDANCY,
                              help='纠错冗余比例 (0.1-0.5)')
    encode_parser.add_argument('-m', '--memory', action='store_true', 
                              help='启用内存优化模式')
    # 解码命令
    decode_parser = subparsers.add_parser('decode', help='从图片解码文件夹')
    decode_parser.add_argument('-s', '--source', required=True, help='安全图片目录')
    decode_parser.add_argument('-p', '--password', required=True, help='解密密码')
    decode_parser.add_argument('-o', '--output', default='restored_data', help='输出目录')

    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细资源使用信息')
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    try:
        if args.command == 'encode':
            if args.redundancy:
                redundancy = max(0.1, min(0.5, args.redundancy))
            else:
                redundancy = DEFAULT_REDUNDANCY
                
            print(f"开始编码文件夹: {args.source}")
            result = encode_folder(
                args.source, 
                args.images, 
                args.password, 
                args.output,
                redundancy
            )
            print(f"成功生成 {len(result)} 张安全图片到 {os.path.abspath(args.output)}")
            
        elif args.command == 'decode':
            print(f"从 {args.source} 解码文件夹...")
            result = decode_images(
                args.source, 
                args.password, 
                args.output
            )
            print(f"文件夹成功恢复至: {os.path.abspath(result)}")
    
    except Fold2ImgError as e:
        print(f"错误: {e.message}")
        if hasattr(e, 'recovery_info') and e.recovery_info:
            print("恢复信息:", json.dumps(e.recovery_info, indent=2))
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n操作已取消")
        sys.exit(1)

if __name__ == '__main__':
    main()
