#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SFA-Miner Setup Script
======================

This script automates the installation and configuration of SFA-Miner,
including all dependencies (LLVM, SVF, Z3) and the build process.

Usage:
    python3 setup.py install    # Full installation
    python3 setup.py build      # Build only
    python3 setup.py deps       # Install dependencies only
    python3 setup.py clean      # Clean build artifacts
"""

import os
import sys
import subprocess
import shutil
import platform
import argparse
from pathlib import Path


class SFAMinerInstaller:
    """SFA-Miner installation manager"""

    def __init__(self, install_dir=None):
        self.project_root = Path(__file__).parent.resolve()
        self.install_dir = Path(install_dir) if install_dir else self.project_root / "install"
        self.build_dir = self.project_root / "build"
        self.system = platform.system()

        # Version configurations
        self.llvm_version = "16.0.0"
        self.cmake_min_version = "3.22"
        self.python_min_version = "3.6"

        # Installation paths
        self.llvm_dir = self.install_dir / f"llvm-{self.llvm_version}.obj"
        self.z3_dir = self.install_dir / "z3.obj"
        self.svf_dir = self.install_dir / "SVF"

    def print_step(self, message):
        """Print formatted step message"""
        print(f"\n{'='*70}")
        print(f"  {message}")
        print(f"{'='*70}\n")

    def run_command(self, cmd, cwd=None, check=True, shell=False):
        """Run shell command with error handling"""
        if isinstance(cmd, list):
            cmd_str = ' '.join(cmd)
        else:
            cmd_str = cmd
            shell = True

        print(f"Running: {cmd_str}")
        try:
            result = subprocess.run(
                cmd if not shell else cmd_str,
                cwd=cwd,
                check=check,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            if result.stdout:
                print(result.stdout)
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e}")
            if e.stdout:
                print(e.stdout)
            if not check:
                return False
            raise

    def check_prerequisites(self):
        """Check if basic prerequisites are installed"""
        self.print_step("Checking Prerequisites")

        prerequisites = {
            'python3': ['python3', '--version'],
            'git': ['git', '--version'],
            'cmake': ['cmake', '--version'],
            'make': ['make', '--version'],
            'gcc/clang': ['gcc', '--version'] if self.system == 'Linux' else ['clang', '--version']
        }

        missing = []
        for name, cmd in prerequisites.items():
            try:
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                print(f"✓ {name} found")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"✗ {name} not found")
                missing.append(name)

        if missing:
            print(f"\nError: Missing prerequisites: {', '.join(missing)}")
            print("\nPlease install missing tools:")
            if self.system == 'Linux':
                print("  sudo apt-get update")
                print(f"  sudo apt-get install -y {' '.join(['git', 'cmake', 'build-essential', 'python3', 'python3-pip'])}")
            elif self.system == 'Darwin':
                print("  brew install git cmake python3")
            return False

        return True

    def install_python_packages(self):
        """Install required Python packages"""
        self.print_step("Installing Python Packages")

        packages = ['bitarray', 'graphviz']

        for package in packages:
            print(f"Installing {package}...")
            self.run_command([sys.executable, '-m', 'pip', 'install', package])

        print("✓ Python packages installed")

    def install_llvm(self):
        """Download and install LLVM 16"""
        self.print_step(f"Installing LLVM {self.llvm_version}")

        if self.llvm_dir.exists() and (self.llvm_dir / "bin" / "clang").exists():
            print(f"✓ LLVM already installed at {self.llvm_dir}")
            return True

        self.install_dir.mkdir(parents=True, exist_ok=True)

        # Determine download URL based on system
        if self.system == 'Linux':
            llvm_package = f"clang+llvm-{self.llvm_version}-x86_64-linux-gnu-ubuntu-18.04"
            llvm_url = f"https://github.com/llvm/llvm-project/releases/download/llvmorg-{self.llvm_version}/{llvm_package}.tar.xz"
        elif self.system == 'Darwin':
            llvm_package = f"clang+llvm-{self.llvm_version}-x86_64-apple-darwin"
            llvm_url = f"https://github.com/llvm/llvm-project/releases/download/llvmorg-{self.llvm_version}/{llvm_package}.tar.xz"
        else:
            print(f"Unsupported system: {self.system}")
            return False

        llvm_archive = self.install_dir / f"{llvm_package}.tar.xz"

        # Download
        if not llvm_archive.exists():
            print(f"Downloading LLVM from {llvm_url}...")
            self.run_command(['wget', '-O', str(llvm_archive), llvm_url], cwd=self.install_dir)

        # Extract
        print(f"Extracting LLVM...")
        self.run_command(['tar', 'xf', llvm_archive.name], cwd=self.install_dir)

        # Rename to standard directory
        extracted_dir = self.install_dir / llvm_package
        if extracted_dir.exists() and not self.llvm_dir.exists():
            extracted_dir.rename(self.llvm_dir)

        print(f"✓ LLVM installed at {self.llvm_dir}")
        return True

    def install_z3(self):
        """Clone and build Z3 theorem prover"""
        self.print_step("Installing Z3 Theorem Prover")

        if self.z3_dir.exists() and (self.z3_dir / "lib" / "libz3.so").exists():
            print(f"✓ Z3 already installed at {self.z3_dir}")
            return True

        z3_src = self.install_dir / "z3-src"

        # Clone Z3
        if not z3_src.exists():
            print("Cloning Z3 repository...")
            self.run_command(['git', 'clone', 'https://github.com/Z3Prover/z3.git', str(z3_src)])

        # Build Z3
        print("Building Z3...")
        self.run_command([sys.executable, 'scripts/mk_make.py', '--prefix', str(self.z3_dir)], cwd=z3_src)

        z3_build = z3_src / "build"
        self.run_command(['make', '-j8'], cwd=z3_build)
        self.run_command(['make', 'install'], cwd=z3_build)

        print(f"✓ Z3 installed at {self.z3_dir}")
        return True

    def install_svf(self):
        """Clone and build SVF"""
        self.print_step("Installing SVF (Static Value Flow)")

        if self.svf_dir.exists() and (self.svf_dir / "Release-build" / "bin" / "svf-ex").exists():
            print(f"✓ SVF already installed at {self.svf_dir}")
            return True

        # Set environment variables for SVF build
        env = os.environ.copy()
        env['LLVM_DIR'] = str(self.llvm_dir)
        env['Z3_DIR'] = str(self.z3_dir)

        # Clone SVF
        if not self.svf_dir.exists():
            print("Cloning SVF repository...")
            self.run_command(['git', 'clone', 'https://github.com/SVF-tools/SVF.git', str(self.svf_dir)])

        # Build SVF
        print("Building SVF...")
        build_script = self.svf_dir / "build.sh"

        if build_script.exists():
            self.run_command(['bash', str(build_script)], cwd=self.svf_dir)
        else:
            # Manual build
            svf_build = self.svf_dir / "Release-build"
            svf_build.mkdir(exist_ok=True)

            self.run_command([
                'cmake', '..',
                f'-DCMAKE_BUILD_TYPE=Release',
                f'-DLLVM_DIR={self.llvm_dir}',
                f'-DZ3_DIR={self.z3_dir}'
            ], cwd=svf_build)

            self.run_command(['make', '-j8'], cwd=svf_build)

        print(f"✓ SVF installed at {self.svf_dir}")
        return True

    def build_sfa_miner(self):
        """Build SFA-Miner SVF driver"""
        self.print_step("Building SFA-Miner")

        # Create build directory
        self.build_dir.mkdir(exist_ok=True)

        # Set environment variables
        env = os.environ.copy()
        env['LLVM_DIR'] = str(self.llvm_dir)
        env['Z3_DIR'] = str(self.z3_dir)
        env['SVF_DIR'] = str(self.svf_dir)

        # CMake configure
        print("Configuring with CMake...")
        cmake_cmd = [
            'cmake', str(self.project_root),
            f'-DLLVM_DIR={self.llvm_dir}',
            f'-DZ3_DIR={self.z3_dir}',
            f'-DSVF_DIR={self.svf_dir}'
        ]

        result = subprocess.run(
            cmake_cmd,
            cwd=self.build_dir,
            env=env,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)
            raise RuntimeError("CMake configuration failed")

        # Build
        print("Building SFA-Miner...")
        self.run_command(['make', '-j8'], cwd=self.build_dir)

        # Create bin directory and copy binary
        bin_dir = self.project_root / "bin"
        bin_dir.mkdir(exist_ok=True)

        svf_ex = self.build_dir / "svf-ex"
        if svf_ex.exists():
            shutil.copy(svf_ex, bin_dir / "svf-ex")
            print(f"✓ svf-ex copied to {bin_dir}")

        print("✓ SFA-Miner built successfully")

    def create_env_file(self):
        """Create environment setup file"""
        self.print_step("Creating Environment Configuration")

        env_file = self.project_root / "env.sh"

        env_content = f"""#!/bin/bash
# SFA-Miner Environment Configuration
# Auto-generated by setup.py

PROJECTHOME={self.project_root}
export LLVM_DIR={self.llvm_dir}
export Z3_DIR={self.z3_dir}
export SVF_DIR={self.svf_dir}

# Update PATH
export PATH=$SVF_DIR/Release-build/bin:$LLVM_DIR/bin:$PROJECTHOME/bin:$PATH

# Update library path
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    export LD_LIBRARY_PATH=$Z3_DIR/lib:$LLVM_DIR/lib:$LD_LIBRARY_PATH
elif [[ "$OSTYPE" == "darwin"* ]]; then
    export DYLD_LIBRARY_PATH=$Z3_DIR/lib:$LLVM_DIR/lib:$DYLD_LIBRARY_PATH
fi

echo "SFA-Miner environment loaded"
echo "  LLVM: $LLVM_DIR"
echo "  Z3: $Z3_DIR"
echo "  SVF: $SVF_DIR"
echo ""
echo "Run: python3 SFAMiner.py --help"
"""

        with open(env_file, 'w') as f:
            f.write(env_content)

        env_file.chmod(0o755)
        print(f"✓ Environment file created: {env_file}")
        print(f"\nTo load environment, run: source {env_file}")

    def clean(self):
        """Clean build artifacts"""
        self.print_step("Cleaning Build Artifacts")

        dirs_to_clean = [self.build_dir, self.project_root / "bin"]

        for dir_path in dirs_to_clean:
            if dir_path.exists():
                print(f"Removing {dir_path}...")
                shutil.rmtree(dir_path)

        print("✓ Clean complete")

    def install_all(self):
        """Run complete installation"""
        print(f"""
╔════════════════════════════════════════════════════════════════════╗
║                     SFA-Miner Installer                            ║
║                                                                    ║
║  This will install:                                                ║
║    - LLVM {self.llvm_version}                                                    ║
║    - Z3 Theorem Prover                                             ║
║    - SVF (Static Value Flow)                                       ║
║    - SFA-Miner tools                                               ║
║                                                                    ║
║  Installation directory: {str(self.install_dir):<40} ║
╚════════════════════════════════════════════════════════════════════╝
        """)

        try:
            # Check prerequisites
            if not self.check_prerequisites():
                return False

            # Install Python packages
            self.install_python_packages()

            # Install dependencies
            self.install_llvm()
            self.install_z3()
            self.install_svf()

            # Build SFA-Miner
            self.build_sfa_miner()

            # Create environment file
            self.create_env_file()

            print(f"""
╔════════════════════════════════════════════════════════════════════╗
║                  Installation Complete!                            ║
╚════════════════════════════════════════════════════════════════════╝

Next steps:
  1. Load environment:
     $ source env.sh

  2. Test installation:
     $ ./compile.sh example.c
     $ python3 SFAMiner.py -s=SymbolicAPIPathGenerator -d=test.db -i=. -o=./output -a=openssl

  3. See README.md for full usage instructions

For issues, visit: https://github.com/JiangJias/SFA-Miner/issues
            """)

            return True

        except Exception as e:
            print(f"\n✗ Installation failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SFA-Miner Setup Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 setup.py install              # Full installation
  python3 setup.py build                # Build only
  python3 setup.py deps                 # Install dependencies only
  python3 setup.py clean                # Clean build artifacts
  python3 setup.py install --prefix=/opt/sfa-miner
        """
    )

    parser.add_argument(
        'command',
        choices=['install', 'build', 'deps', 'clean'],
        help='Installation command'
    )

    parser.add_argument(
        '--prefix',
        default=None,
        help='Installation prefix directory (default: ./install)'
    )

    args = parser.parse_args()

    installer = SFAMinerInstaller(install_dir=args.prefix)

    if args.command == 'clean':
        installer.clean()
    elif args.command == 'deps':
        installer.check_prerequisites()
        installer.install_python_packages()
        installer.install_llvm()
        installer.install_z3()
        installer.install_svf()
    elif args.command == 'build':
        installer.build_sfa_miner()
        installer.create_env_file()
    elif args.command == 'install':
        success = installer.install_all()
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
