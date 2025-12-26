import glob
import subprocess

files = glob.glob('./include/**/*.h', recursive=True)
files += glob.glob('./src/**/*.c', recursive=True)
files += glob.glob("./src/**/CMakeLists.txt", recursive=True)
files += ['CMakeLists.txt']
subprocess.run(['nvim'] + files)
