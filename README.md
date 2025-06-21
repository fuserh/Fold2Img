# Fold2Img - 文件夹安全嵌入图片工具

Fold2Img 是一个强大的工具，可以将整个文件夹加密后嵌入到图片中，实现数据的隐蔽存储和安全传输。支持纠错码恢复、AES-256加密和多种图片格式，确保您的数据安全可靠。

## 主要功能

- 🔒 **军用级加密**：使用 AES-256-GCM 加密算法保护数据
- 🔧 **智能纠错**：内置 Reed-Solomon 纠错码，可恢复损坏数据
- 🖼️ **多格式支持**：支持 PNG、JPEG、BMP、WebP 等主流图片格式
- ⚙️ **资源优化**：自动内存管理，支持大文件处理
- 🔁 **容错设计**：即使部分图片损坏，也能恢复完整数据
- 🧩 **灵活载体**：可使用现有图片或自动生成载体图片

## 安装指南

### 依赖安装

```bash
# 安装 Python 3.8+
sudo apt update
sudo apt install python3 python3-pip

# 安装系统依赖 (Ubuntu/Debian)
sudo apt install build-essential python3-dev libjpeg-dev zlib1g-dev

# 安装 Python 依赖
pip install -r requirements.txt
```

### 依赖列表 (requirements.txt)
```
Pillow==10.0.0
pycryptodome==3.19.0
reedsolo==1.7.0
tqdm==4.66.1
psutil==5.9.6
```

## 使用说明

### 编码文件夹到图片

```bash
python fold2img.py encode \
  -s /path/to/source_folder \
  -i /path/to/carrier_images \
  -p your_strong_password \
  -o /output/directory \
  -r 0.3  # 可选：纠错冗余比例 (0.1-0.5)
```

程序将：
1. 计算所需图片数量
2. 使用现有图片（如果可用）
3. 自动生成缺失的载体图片
4. 创建带加密数据的安全图片

### 从图片恢复文件夹

```bash
python fold2img.py decode \
  -s /path/to/secured_images \
  -p your_strong_password \
  -o /restore/directory
```

## 使用示例

### 示例 1：基本使用
```bash
# 将文档文件夹编码到图片
python fold2img.py encode -s ~/Documents -i ./carriers -p S3cur3P@ss -o ./output

# 从安全图片恢复文档
python fold2img.py decode -s ./output -p S3cur3P@ss -o ./restored_docs
```

### 示例 2：使用自定义图片
```bash
# 准备至少 20 张图片在 ./my_photos 中
python fold2img.py encode -s ~/secret_data -i ./my_photos -p MyPass123 -o ./hidden_data
```

### 示例 3：增加容错能力
```bash
# 使用 40% 冗余提高恢复能力
python fold2img.py encode -s ~/important_files -i ./pictures -p Str0ngP@ss -r 0.4 -o ./protected
```

## 技术细节

### 文件结构
```
MAGIC_NUMBER (4B) | 块索引 (4B) | 数据长度 (4B) | 加密数据 (变长)
```

### 处理流程
1. **压缩**：使用 tar.xz 压缩文件夹
2. **加密**：AES-256-GCM 加密数据
3. **纠错**：添加 Reed-Solomon 纠错码
4. **分块**：分割数据为等大小块
5. **嵌入**：将数据块嵌入图片文件

### 恢复能力
- 支持最多 `(冗余比例 * 100)%` 的数据损坏恢复
- 即使部分图片丢失，仍可恢复完整数据

## 注意事项

1. **内存要求**：
   - 处理大文件时需要足够内存
   - 建议可用内存 > 文件大小的 1.5 倍

2. **图片要求**：
   - 最小图片尺寸：1KB + 嵌入数据
   - 推荐使用 >100KB 的图片作为载体

3. **安全建议**：
   - 使用强密码（12+字符，混合大小写、数字和符号）
   - 安全存储密码，丢失将无法恢复数据
   - 分散存储生成的图片以增强安全性

4. **性能提示**：
   - 增加冗余比例会提高文件大小但增强恢复能力
   - 大文件处理可能需要较长时间（启用 `-v` 查看进度）

## 许可证

本项目采用 AGPLv3 许可证 - 详见 [LICENSE](LICENSE) 文件。

---

**提示**：处理完成后，安全图片看起来与普通图片无异，但内含加密数据。建议将生成的图片与其他普通图片混合存储，增强隐蔽性。
