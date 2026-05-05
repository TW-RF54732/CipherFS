# CipherFS

CipherFS 是一款專為 Linux 設計的高性能、唯讀加密虛擬檔案系統 (FUSE)。它專注於大規模數據存取的效率，並內建了強大的「脅迫防禦」機制。

## 核心特性

### 安全架構
- **KDF**: 使用 Argon2id 進行高強度金鑰衍生。
- **加密算法**: 使用 ChaCha20-Poly1305 (AEAD) 提供高性能且具備完整性驗證的加密。
- **金鑰管理**: 分離資料金鑰 (DEK) 與主金鑰 (KEK)，更換密碼無需重新加密所有資料。

### 高性能與擴展性
- **並行處理**: 採用 Linux 專有的並行讀取技術，徹底消除 FUSE 讀取瓶頸。
- **隨機存取**: 4MB 固定區塊設計與獨立 Nonce 衍生，實現秒級隨機尋址與局部解密。
- **低負載索引**: 優化的平坦索引映射，輕鬆處理數百萬級別檔案。

### 脅迫保護 (Duress Protection)
- **脅迫密碼**: 支援設定第二組「脅迫密碼」，輸入後將立即且安靜地銷毀資料金鑰 (DEK)。
- **物理中和**: 一旦觸發，該容器將永遠無法解碼，為極端情況提供「焦土策略」級別的安全保障。

### CLI 工具功能
- **自動更新**: 內建 `update` 指令，可直接從 GitHub 獲取最新穩定版。
- **優雅卸載**: 整合 Linux 信號處理，支援 Ctrl+C 自動安全卸載。

## 安裝

CipherFS 專為 Linux 平台設計，請確保您的系統已安裝 `fuse3` 與 `libfuse3-dev`。

### 從穩定版下載 (推薦)
1. 前往 [Releases](https://github.com/TW-RF54732/CipherFS/releases) 下載最新的二進位檔。
2. 賦予執行權限：`chmod +x cipherfs`。

### 從原始碼編譯
```bash
cargo build --release
```

## 使用方法

### 打包目錄 (Pack)
```bash
./cipherfs pack <source_directory> [output_file]
```

### 掛載容器 (Mount)
```bash
./cipherfs mount <container.cfs> <mount_point>
```
掛載後為唯讀模式。按 **Ctrl+C** 即可優雅卸載。

### 提取資料 (Extract)
```bash
./cipherfs extract <container.cfs> <output_dir>
```

### 自動更新 (Update)
```bash
./cipherfs update
```

## 平台支援

- **原生支援**: Linux (核心版本 5.4+ 推薦)
- **依賴**: FUSE3

## 授權

MIT License
