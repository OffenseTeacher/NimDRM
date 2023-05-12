# NimDRM
<p align="center">
    <img width="500" src="https://github.com/OffenseTeacher/NimDRM/blob/main/NimDRM.gif">
</p>
An experiment in improving existing anti-copy techniques. This one forces the payload to request the decryption key to a license server. This server decides to return the key depending on various anti-tampering and fingerprint checks
<br><br>Any miscalculated move from the blue team and the license gets permanently banned, preventing complete behavior analysis.
<br><br>For more information regarding Offensive developpment, see: [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)

## How to use
- Install Nim on Linux
- Clone this repo
- Change values if desired, then compile Encrypt.nim
- Copy the output to NimDRM.nim, adjust the other settings and compile
- Start the python license server
- Execute the payload on arbitrary systems

## How to cross-compile from Linux to Windows
- nim c -d=mingw -d=release --app=console --cpu=amd64 Encrypt.nim
- nim c -d=mingw -d=release --app=console --cpu=amd64 NimDRM.nim
