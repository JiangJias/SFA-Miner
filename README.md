# SFA-Miner

SFA-Miner is a static analysis tool for mining API usage patterns and detecting API misuse vulnerabilities in large-scale C/C++ codebases. It combines Symbolic API Path (SAP) generation with frequent subgraph mining to automatically extract API usage rules and identify violations.

## Features

- **Symbolic API Path Generation**: Leverages SVF (Static Value Flow) for precise pointer analysis and control flow tracking
- **Frequent Subgraph Mining**: Automatically discovers common API usage patterns across codebases
- **API Misuse Detection**: Identifies code that violates learned API usage rules
- **Scalable Analysis**: Supports large projects like Linux kernel, OpenSSL, and FFmpeg
- **Parallel Processing**: Multi-threaded execution for improved performance

## Architecture

```
Input: LLVM Bitcode (.bc/.ll files)
    ↓
[1] SymbolicExecutor (SVF-based)
    → Pointer analysis & data flow extraction
    → Symbolic API Path (SAP) generation
    ↓
[2] IndexBuilder
    → Database indexing
    → Location & item tables
    ↓
[3] FrequentSubgraphMiner
    → Pattern mining (support & confidence)
    → API usage rule extraction
    ↓
[4] SFAVote & SFAGenerate
    → Rule voting & selection
    ↓
[5] Translator
    → Violation detection
    ↓
[6] Output
    → Violation reports & visualizations
```

## Prerequisites

### System Requirements
- Ubuntu 18.04+ or macOS 10.15+
- CMake 3.22+
- Python 3.6+
- 16GB+ RAM (for large projects)

### Dependencies
- **LLVM 16.x** with Clang
- **SVF** (Static Value Flow Analysis Framework)
- **Z3 Theorem Prover**
- Python packages: `bitarray`, `graphviz`

## Installation

### Option 1: Using setup.py

```bash
# Clone the repository
git clone https://github.com/JiangJias/SFA-Miner.git
cd SFA-Miner

# Install dependencies and build
python3 setup.py install
```

### Option 2: Using Docker

```bash
# Build Docker image
docker build -t sfa-miner .

# Run container
docker run -it -v $(pwd)/data:/workspace/data sfa-miner
```

### Option 3: Manual Installation

1. **Install LLVM 16**:
```bash
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-16.0.0/clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
tar xf clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
export LLVM_DIR=$(pwd)/clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04
```

2. **Install Z3**:
```bash
git clone https://github.com/Z3Prover/z3.git
cd z3
python scripts/mk_make.py
cd build
make -j8
sudo make install
```

3. **Install SVF**:
```bash
git clone https://github.com/SVF-tools/SVF.git
cd SVF
source build.sh
```

4. **Set environment variables**:
```bash
source env.sh
```

5. **Build SFA-Miner**:
```bash
mkdir build && cd build
cmake ..
make
```

6. **Install Python dependencies**:
```bash
pip3 install bitarray graphviz
```

## Usage

### Basic Workflow

1. **Compile target code to LLVM bitcode**:
```bash
./compile.sh target.c
# This generates target.ll
```

2. **Generate Symbolic API Paths**:
```bash
python3 SFAMiner.py -s=SymbolicAPIPathGenerator \
    -d=SFA.db \
    -i=/path/to/bitcode/files \
    -o=/path/to/output \
    -a=openssl
```

3. **Mine Frequent Patterns**:
```bash
python3 SFAMiner.py -s=FrequentSubgraphMiner \
    -d=SFA.db \
    -o=/path/to/output \
    -a=openssl
```

4. **Detect Violations**:
```bash
python3 SFAMiner.py -s=Translator \
    -d=SFA.db \
    -o=/path/to/output \
    -a=openssl
```

5. **Output Results**:
```bash
# Output violations
python3 SFAMiner.py -s=outputViolations \
    -d=SFA.db \
    -o=/path/to/output \
    -a=openssl

# Output extracted rules
python3 SFAMiner.py -s=outputRules \
    -d=SFA.db \
    -o=/path/to/output \
    -a=openssl

# Visualize rules (requires graphviz)
python3 SFAMiner.py -s=drawRules \
    -d=SFA.db \
    -o=/path/to/output \
    -a=openssl
```

### Command-Line Options

```
Usage: python3 SFAMiner.py [OPTIONS]

Required Arguments:
  -s, --step STEP            Analysis step to execute:
                             - SymbolicAPIPathGenerator
                             - FrequentSubgraphMiner
                             - SFACombine
                             - Translator
                             - outputRules
                             - outputViolations
                             - drawRules
                             - drawPaths

  -d, --database DB          SQLite database file path
  -a, --app APP              Application name (openssl/linux/ffmpeg)

Optional Arguments:
  -i, --inputDir DIR         Input directory containing .bc/.ll files
  -o, --outputDir DIR        Output directory for results
  --debug                    Enable debug mode
```

### Supported Applications

The tool has been tested and optimized for:
- **OpenSSL**: Cryptographic library
- **Linux Kernel**: Operating system kernel
- **FFmpeg**: Multimedia framework

## Configuration

Key parameters can be adjusted in `SFAMiner.py`:

```python
MIN_SUPPORT = 10           # Minimum support count
MIN_CONFIDENCE = 0.5       # Minimum confidence threshold
SFA_VOTE = 0.9            # SFA voting threshold
PROCESSOR = 24            # Number of parallel workers
TIMEOUT = 600             # Timeout in seconds
```

## Example

Analyze a simple C program:

```bash
# Compile example
./compile.sh example.c

# Run analysis
python3 SFAMiner.py -s=SymbolicAPIPathGenerator \
    -d=example.db \
    -i=. \
    -o=./output \
    -a=openssl
```

## Project Structure

```
SFA-Miner/
├── SFAMiner.py              # Main analysis engine (2940 lines)
├── src/
│   └── svf-ex.cpp           # SVF driver program (302 lines)
├── CMakeLists.txt           # Build configuration
├── compile.sh               # LLVM IR compilation script
├── env.sh                   # Environment setup script
├── setup.py                 # Python package installer
├── Dockerfile               # Container configuration
├── example.c                # Example C code
└── openssl/                 # OpenSSL source (submodule)
```

## Output Format

### Rules Database
Rules are stored in SQLite with the following schema:
- **Items**: API calls and conditional predicates
- **Locations**: Source file and function information
- **Rules**: Extracted API usage patterns with support/confidence
- **Violations**: Detected rule violations with locations

### Visualization
GraphViz DOT files are generated for:
- API usage patterns
- Control flow graphs
- Violation traces

## Performance Tips

1. **Parallel Processing**: Adjust `PROCESSOR` parameter based on CPU cores
2. **Memory Usage**: Large projects may require 32GB+ RAM
3. **Timeout**: Increase `TIMEOUT` for complex functions
4. **Filtering**: Customize `notBugAPIPatterns` to reduce false positives

## Troubleshooting

### Common Issues

**Issue**: `svf-ex` not found
```bash
# Solution: Rebuild and check PATH
cmake . && make
export PATH=$(pwd)/bin:$PATH
```

**Issue**: LLVM version mismatch
```bash
# Solution: Verify LLVM version
llvm-config --version  # Should be 16.x.x
```

**Issue**: Z3 library not found
```bash
# Solution: Set library path
export LD_LIBRARY_PATH=/path/to/z3/build:$LD_LIBRARY_PATH
```

## Contributing

This is a research prototype. Contributions are welcome:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Citation

If you use SFA-Miner in your research, please cite our paper:

```bibtex
@inproceedings{sfa-miner,
  title={SFA-Miner: Mining API Usage Patterns via Symbolic Frequent Subgraph Analysis},
  author={...},
  booktitle={...},
  year={2024}
}
```

## License

[To be determined - pending paper publication]

## Contact

For questions or issues, please open an issue on GitHub or contact the authors.

## Acknowledgments

- **SVF Project**: Static Value Flow analysis framework
- **LLVM Project**: Compiler infrastructure
- **Z3 Solver**: Theorem prover from Microsoft Research
