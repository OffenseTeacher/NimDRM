import winim
import nimcrypto
import os
import zippy
import puppy
import json
import dynlib
import std/sha1
import strutils except fromHex
from winim/lean import MessageBox

var 
    iv: seq[byte] = fromHex("5342524E5558545A48465A4D4C55454B") #Replace me
    msgTitle = "CC81AD2FAA0E2427A76AF35F13FEDF5C9F0304AA49E0BD41DFDEE1B36C" #Replace me
    msgContent = "CC81AD2FAA0E2427A76AF35513F4DF5A9F4E0E97762E02BF94BBC0E73656964E3A1ED6" ##Replace me
    license = "e95a94f6-695e-4418-90ef-f07bb3e75025" #Make sure this license is authorized in the license server
    licenseServer = "http://192.168.2.89:5000/authorize" #Replace me
    key = ""

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

type
  ND_LDR_DATA_TABLE_ENTRY* {.bycopy.} = object
    InMemoryOrderLinks*: LIST_ENTRY
    InInitializationOrderLinks*: LIST_ENTRY
    DllBase*: PVOID
    EntryPoint*: PVOID
    SizeOfImage*: ULONG
    FullDllName*: UNICODE_STRING
    BaseDllName*: UNICODE_STRING

  PND_LDR_DATA_TABLE_ENTRY* = ptr ND_LDR_DATA_TABLE_ENTRY
  ND_PEB_LDR_DATA* {.bycopy.} = object
    Length*: ULONG
    Initialized*: UCHAR
    SsHandle*: PVOID
    InLoadOrderModuleList*: LIST_ENTRY
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY

  PND_PEB_LDR_DATA* = ptr ND_PEB_LDR_DATA
  ND_PEB* {.bycopy.} = object
    Reserved1*: array[2, BYTE]
    BeingDebugged*: bool
    Reserved2*: array[1, BYTE]
    Reserved3*: array[2, PVOID]
    Ldr*: PND_PEB_LDR_DATA

  PND_PEB* = ptr ND_PEB

proc getKey(): string
proc cryptUtils(input: string, envkey: string): seq[byte] =
    var
        dctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        enctext: seq[byte] = fromHex(input)
        dectext = newSeq[byte](len(enctext))

    var expandedkey = sha256.digest(envkey)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

    dctx.init(key, iv)
    dctx.decrypt(enctext, dectext)
    dctx.clear()
    return uncompress(dectext)

proc decryptWrapper(sc: string): seq[byte] =
    var key = getKey()
    return cryptUtils(sc, key)

when defined(WIN64):
  const
    PEB_OFF* = 0x30
else:
  const
    PEB_OFF* = 0x60

proc getPEBPointer*(p: culong): P_PEB {. 
    header: 
        """#include <windows.h>
           #include <winnt.h>""", 
    importc: "__readgsqword"
.}


proc checkAntiDebug*() =
    var Peb: PPEB = getPEBPointer(PEB_OFF)
    var BeingDebugged = bool(Peb.BeingDebugged)
    if (BeingDebugged):
      quit() #Quit could be replace by self delete function

proc checkForIDA() =
    for path in walkFiles("*"):
        if path.contains("id0") or path.contains("id1") or path.contains("id2"):
            quit() #Quit could be replace by self delete function

proc checkOnDiskIntegrity*(): SecureHash =
    return secureHashFile(getAppFilename())

proc licensingServerManager(fileHash: SecureHash, hostname: string, secret: string): string =
    var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    let body = %*{
        "license": license,
        "file_hash": $fileHash,
        "host": hostname,
        "secret": secret
    }

    try:
        let req = Request(
        url: parseUrl(licenseServer),
        verb: "post",
        headers: @[Header(key: "User-Agent", value: userAgent)],
        body: $body
        )
        var res = fetch(req)
        return res.body
    except:
        discard
    
proc getKey(): string =
    if key != "":
        return key
    
    var msvcrt = loadLib("msvcrt")
    var fPtr : pointer = msvcrt.symAddr("getenv")
    var customGetEnv : (proc(arg: cstring) : cstring {.cdecl, gcsafe.}) = cast[(proc(arg: cstring) : cstring {.cdecl, gcsafe.})](fPtr)
    
    checkAntiDebug()
    checkForIDA()
    var fileHash = checkOnDiskIntegrity()
    let hostname = $(customGetEnv("COMPUTERNAME"))
    var storedSecret = ""
    try:
        storedSecret = readFile(getAppFileName() & ":Mr.Bones")
    except:
        discard

    var response = parseJson(licensingServerManager(fileHash, hostname, storedSecret))
    key = response["key"].str
    var secret = response["secret"].str
    if key == "":
        quit(1) #Quit could be replace by self delete function
    
    writeFile(getAppFileName() & ":Mr.Bones", secret)
    return key

proc displayPopupMsg(): void =
    var
        decMsgTitle = toString(decryptWrapper(msgTitle))
        decMsgContent = toString(decryptWrapper(msgContent))

    MessageBox(0,decMsgContent,decMsgTitle,MB_ICONINFORMATION)

when isMainModule:
    displayPopupMsg()
