Jagex Launcher DLL Proxy
-----
A simple chrome_elf DLL proxy that allows one to override the launcher create process command with a custom command of
yours.

### Why?

Was tired of typing my password and didn't want to reverse engineer the Jagex Launcher to see how they did oauth2, so
decided to just hook into `CreateProcessW` and have the launcher feed me the environment variables.

### How to set the custom command

1. Right now it's embedded in the DLL, so you'll have to compile it yourself.
2. Modify the `CUSTOM_LAUNCHER_COMMAND` macro in the main.cc file.

### Usage

1. Rename the original `chrome_elf.dll` to `chrome_elf_original.dll` and leave it be in the same directory as the Jagex
   Launcher.
2. Move the `chrome_elf.dll` from this repository to the same directory as the Jagex Launcher.
3. Should look [something like this](https://i.imgur.com/3MoXGaJ.png).
4. Launch the Jagex Launcher, and try to press the play button to see if launches your custom command.

### How to build

1. Used Visual Studio 2019 to build.
2. Make sure to use the x86 Release configuration since the DLL is 32-bit.
3. Here is my [CLion toolchain config for reference](https://i.imgur.com/VyaN8CI.png).