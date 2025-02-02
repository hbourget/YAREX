<img src=https://i.imgur.com/3xERQeP.png height=150 width=350>

# YAREX
![MIT License](https://img.shields.io/badge/License-MIT-black)
![Bash Script](https://img.shields.io/badge/4.0+-Bash-green)
![Bash Script](https://img.shields.io/badge/5.1+-Powershell-blue)


<b>YAREX</b> was initially created to optimize file-system-wide YARA scans, that are taking ages, on even on higher end machines. It is a user-friendly script designed to simplify those scans, with interactive prompts.

## Features

- **♻️ Automatic rules updates**: Fetches the latest YARA rules from [YARA Forge](https://github.com/YARAHQ/yara-forge).
- **📁 Locations**: Specify directories to scan.
- **🚫 Exclusions**: Select specific file types to exclude from scans to make them more efficient.
- **🔨 Parameters**: Max file size, rule set to use, multi-threading
- **📊 Reporting**: Generates a CSV report with the findings. Rule name / File Path / SHA256 hash
- **🔍 Extracting**: Extracts the suspected files.

> All of those features are customizable and/or optional.

## Installation

### macOS & Ubuntu

   ```bash
   brew install coreutils
   brew install yara
   ```

   ```bash
   sudo apt-get update
   sudo apt-get install yara
   ```

   ```bash
   git clone https://github.com/hbourget/yarex.git
   cd yarex
   chmod +x yarex.sh
   ```

### Windows
   Start PowerShell as administrator
   ```bash
   git clone https://github.com/hbourget/yarex.git
   cd yarex
   ```
> The binary is already included in the project, under the /bin directory.

### Other distros: 
Refer to the [YARA GitHub repository](https://github.com/VirusTotal/yara) for more installation instructions.

## Parameters

### 🔍 Size limit recommendations
| **Scan Type**            | **Recommended File Size Limit** |
|-------------------------|------------------------------|
| Fast scanning (low impact) | `10MB – 50MB` |
| Balanced performance & quality | `100MB – 250MB` |
| Thorough scanning (higher resource usage) | `500MB – 1GB` |
| Deep scan (will be very long) | **No limit** (not recommended) |

> You have to convert those values in bytes (binary)! https://www.gbmb.org/mb-to-bytes

### 🛠 Rule sets
| **Need** | **Rule set** | **Description** |
|----------|----------------------|----------------|
| **Fast scan** (Low system impact) | **Core** | Covers essential malware families and threats with minimal overhead. Best for routine monitoring and endpoint scans. |
| **Balanced scan** (More coverage, reasonable performance) | **Extended** | Includes everything from Core + additional signatures for wider threat detection. |
| **Deep scan** (High resource use, exhaustive search) | **Full** | Covers all known threats, including rare and advanced malware. Suited for forensic investigations. |

### 🚫 Exclusions

Exclusions are managed via `.inm` files located in the `./inames` directory. The goal of this is to remove those types of files from the scan, that can cause bottleneck.

**📦 Archives (archives.inm)** `.zip, .rar, .tar, .gz, .7z, .bz2, .xz, .cab, .tgz`

**🎵 Audios (audio.inm)** `.mp3, .wav, .aac, .flac, .ogg, .wma, .m4a, .alac, .opus, .amr`

**🖥️ Virtual machines (vm.inm)** `.ova, .ovf, .vhd, .vhdx, .vmdk, .vdi, .qcow2, .raw, .img`

**🗄️ Databases (databases.inm)** `.sql, .db, .sqlite, .sqlite3, .accdb`

**🖼️ Image Files (images.inm)** `.jpg, .jpeg, .png, .gif, .bmp, .tiff, .webp, .svg, .heic, .ico`

**🎥 Video Files (video.inm)** `.mp4, .mkv, .avi, .mov, .wmv, .flv, .webm, .m4v, .3gp, .mpeg, .mpg`

## Usage

### GNU/Linux & macOS :
Run the YAREX script with privileges:

```bash
sudo ./yarex.sh
```

### Windows :
Run Powershell as **administrator** and temporarily bypass the powershell restrictions :
```
Set-ExecutionPolicy Unrestricted
./yarex.ps1
```

> The script is interactive and will prompt you with options.

## License

This project is licensed under the [MIT License](./LICENSE).
