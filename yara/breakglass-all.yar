rule SERPENTINE_CLOUD_Loader_DLL {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SERPENTINE#CLOUD Mingw-w64 loader DLLs (loader_N.dll) used for process injection into explorer.exe"
        hash1 = "b2fa2988c6ad45276eaf737416fafb8328d90a452eff47f5ca5b9770f87c87bd"
        hash2 = "ce0a323ff6a3988f8550144bde76dfd250fcae689c73ce319e31c3006fc78b19"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $export = "Run" ascii
        $target = "explorer.exe" ascii wide
        $loader_pattern = "loader_" ascii
        $compiler = "GCC: (GNU) 13-win32" ascii
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "CreateToolhelp32Snapshot" ascii
        $api5 = "Process32First" ascii
        $api6 = "OpenProcess" ascii
        $mingw = "Mingw-w64 runtime failure:" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50KB and
        $export and
        $target and
        $loader_pattern and
        $compiler and
        4 of ($api*) and
        $mingw
}

rule SERPENTINE_CLOUD_Encrypted_Payload {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SERPENTINE#CLOUD encrypted own.enc payloads (16-byte XOR key prefix + Donut shellcode)"
        hash1 = "7ad06185c4f8d97db51b93d21aa9888ff21b9688b195fdaf6e3770a995e8d1a5"
        hash2 = "fe29f7972f68cf98c2a88cf43d68fea8695c55b56bb1fb7acc4d1eed8d732ed3"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        // After 16-byte XOR decryption, Donut shellcode starts with CALL +large_offset
        // The XOR pattern creates distinctive byte patterns
        // We match on file size (84070 bytes exactly for this wave) and high entropy
        $not_pe = { 4D 5A }
    condition:
        not $not_pe at 0 and
        filesize == 84070 and
        // High entropy check via absence of long null runs
        not uint32(0) == 0x00000000 and
        not uint32(4) == 0x00000000
}

rule SERPENTINE_CLOUD_Donut_Shellcode {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects decrypted SERPENTINE#CLOUD Donut shellcode (CALL+POP pattern with instance structure)"
        hash1 = "746e42de473b3f78f64eb65e7b3468874f881219b7445d6648dcfc15f5489a5c"
        hash2 = "b25f0c7becfa5ea8e97c06a612f87e3802d953782ece6d69b2c43804b939c276"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        // CALL +0x113c0 followed by data
        $call_pattern = { E8 C0 13 01 00 }
        // Donut decoder stub: POP RCX; AND RSP,-10; PUSH RCX
        $decoder_stub = { 59 48 83 E4 F0 51 }
        // Process injection pattern at specific offset
        $inject_pattern = { 33 FF 48 8B D9 39 B9 38 02 00 00 }
    condition:
        $call_pattern at 0 and
        ($decoder_stub or $inject_pattern)
}

rule SERPENTINE_CLOUD_Dropper_BAT {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SERPENTINE#CLOUD stage 1 dropper BAT with WebDAV delivery and dual injection"
        hash = "ad888d6ba84ba839ebc1a0a9d5e4cca030c2b58624af828cdc932624e1ba73b4"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $dav = "trycloudflare.com@SSL\\DavWWWRoot" ascii nocase
        $svc = "net start WebClient" ascii nocase
        $rundll = "rundll32.exe" ascii nocase
        $run_export = ",Run" ascii
        $startup = "WindowsSecurityHealth.bat" ascii
        $lock = "wupd.lock" ascii
        $callback = "/s/!ID!/" ascii
        $self_delete = "del \"%~f0\"" ascii nocase
    condition:
        filesize < 10KB and
        $dav and
        $rundll and
        $run_export and
        3 of ($svc, $startup, $lock, $callback, $self_delete)
}

rule SERPENTINE_CLOUD_Inner_BAT_PEM_Payload {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SERPENTINE#CLOUD inner BAT files with base64 payloads disguised as PEM certificates"
        hash1 = "deploy_2a1m0b.bat"
        hash2 = "configure_6t71fu.bat"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $pem_begin = "-----BEGIN CERTIFICATE-----" ascii
        $pem_end = "-----END CERTIFICATE-----" ascii
        $certutil = "certutil -decode" ascii nocase
        $rundll = "rundll32.exe" ascii nocase
        $mz_b64 = "TVqQAAMAAAAEAAAA" ascii
        $bat_header = "@echo off" ascii nocase
    condition:
        filesize > 100KB and
        filesize < 200KB and
        $bat_header and
        $pem_begin and
        $pem_end and
        $certutil and
        $rundll and
        $mz_b64
}

rule SERPENTINE_CLOUD_Imphash_Cluster {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects PE files matching the SERPENTINE#CLOUD loader imphash cluster"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50KB and
        pe.imphash() == "efd7f22fecb87f90fef74b8027a9ff28"
}
/*
 * YARA Rules for MoliyaviyTahlilUZ.jar NetSupport RAT Dropper
 * Author: GHOST - Breakglass Intelligence
 * Date: 2026-03-31
 * TLP: WHITE
 */

rule NetSupport_JAR_Dropper_UzbekLure {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects the MoliyaviyTahlilUZ.jar NetSupport RAT dropper targeting Uzbekistan"
        hash = "0133a8a0bc4521eb39f24563c0866fe93eb0501507a920abbae5692f60c89220"
        tlp = "WHITE"
        malware_family = "NetSupport RAT"
        
    strings:
        $jar_magic = { 50 4B 03 04 }
        $main_class = "MoliyaviyTahlilIlovasi" ascii
        $c2_url = "my-xarid.com/api/v5/" ascii
        $m1 = "bajarishMoliyaviyTahlil" ascii
        $m2 = "aniqlashMoliyaviyServer" ascii
        $m3 = "tekshirishKompyuterRuxsatnomasi" ascii
        $m4 = "koorsatishMoliyaviyTahlilOynasi" ascii
        $m5 = "yaratishMoliyaviyYuklovchi" ascii
        $m6 = "qoshishRegistrMoliyaviy" ascii
        $v1 = "SERVER_MANZILLARI" ascii
        $v2 = "TIZIM_KOMPONENTLARI" ascii
        $ns1 = "client32.exe" ascii
        $ns2 = "client32.ini" ascii
        $ns3 = "remcmdstub.exe" ascii
        $ns4 = "NSM.lic" ascii
        $ns5 = "HTCTL32.DLL" ascii
        $ns6 = "AudioCapture.dll" ascii
        $ua1 = "MoliyaviyTahlil/1.0" ascii
        $ua2 = "Moliyaviy-Tahlil-Agent" ascii
        $persist1 = "moliyaviy_tahlil_loader.bat" ascii
        $persist2 = "moliyaviy_tahlil_avto.bat" ascii
        $lure1 = "Inspeksiya" ascii wide
        $lure2 = "BUXGALTERIYA ILOVASI" ascii wide
        
    condition:
        $jar_magic at 0 and filesize < 100KB and (
            ($c2_url) or
            ($main_class and 3 of ($m*)) or
            (2 of ($v*) and 3 of ($ns*)) or
            (1 of ($ua*) and 2 of ($persist*)) or
            (2 of ($lure*) and 2 of ($ns*))
        )
}

rule NetSupport_JAR_Dropper_Generic_UzbekTheme {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Generic detection for Uzbek-themed JAR droppers deploying NetSupport RAT"
        tlp = "WHITE"
        
    strings:
        $jar = { 50 4B 03 04 }
        $uz1 = "Moliyaviy" ascii nocase
        $uz2 = "Buxgalteriya" ascii nocase
        $uz3 = "Inspeksiya" ascii nocase
        $uz4 = "soliq" ascii nocase
        $uz5 = "tahlil" ascii nocase
        $ns1 = "client32.exe" ascii
        $ns2 = "HTCTL32.DLL" ascii
        $ns3 = "remcmdstub.exe" ascii
        $ns4 = "NSM.lic" ascii
        $java1 = "java/net/HttpURLConnection" ascii
        $java2 = "java/nio/file/Files" ascii
        
    condition:
        $jar at 0 and filesize < 200KB and
        2 of ($uz*) and 2 of ($ns*) and all of ($java*)
}

rule NetSupport_RAT_Download_BatLoader {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects batch file loader pattern used by this NetSupport RAT campaign"
        tlp = "WHITE"
        
    strings:
        $bat1 = "@echo off" ascii nocase
        $bat3 = /start\s+""\s+\/B\s+"/ ascii
        $bat4 = "client32.exe" ascii nocase
        $name1 = "moliyaviy_tahlil" ascii nocase
        
    condition:
        filesize < 1KB and $bat1 and $bat3 and ($bat4 or $name1)
}
import "pe"

rule Salo_Hotfix_Trojanized_Aliases_Py {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects trojanized Python encodings/aliases.py used in Salo Hotfix campaign. The legitimate aliases.py is modified to include obfuscated command execution via os.system()."
        hash = "0ab588411764cc47f270ca775b90afd8ae5981d118256e18a7b9c4f48e0abeeb"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $header = "Encoding Aliases Support" ascii
        $import_os = "import os" ascii
        $type_a = "typeA = \"/\"" ascii
        $type_q = "typeQ = \"SysWOW64\"" ascii
        $type_r = "typeR = \"Power\"" ascii
        $global_region = "global_region" ascii
        $mem_protect = "mem_protect" ascii
        $ram_protect = "ram_protect" ascii
        $conhost = "conhost" ascii
        $os_system = "os.system(cmd)" ascii
    condition:
        $header and $import_os and 4 of ($type_*,$global_region,$mem_protect,$ram_protect,$conhost,$os_system)
}

rule Salo_Hotfix_PowerShell_Stage {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects the /salo PowerShell payload with XOR-encrypted stage and junk variable obfuscation"
        hash = "bec7c3a4a90d107dd1f19024e44bd77a7ce87344dd68950d6f269855c1ff0f92"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $xor_key = "o6utydhcgf75ks" ascii wide
        $func_name = "reduceShowData" ascii
        $byte_array = "[Byte[]]$useByteArray" ascii
        $exec_pattern = "scriptblock]::Create($decryptedCode)" ascii
        $junk_var = "Get-AzSubscription -Append -TaskPath" ascii
    condition:
        2 of them
}

rule Salo_Hotfix_Decrypted_Injector {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects the decrypted Stage 2 payload containing AMSI bypass and process hollowing code"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $namespace = "CybersecurityMuseum.Workshop" ascii wide
        $class1 = "ProcessPoolprocessor" ascii wide
        $class2 = "PoolprocessionEngine" ascii wide
        $class3 = "PoolprocessionConfig" ascii wide
        $config1 = "PooldataParser" ascii wide
        $target1 = "msfeedssync.exe" ascii wide
        $target2 = "PackagedCWALauncher.exe" ascii wide
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = { 41 6D 73 69 53 63 61 6E 42 75 66 66 65 72 }
        $monitor = "burning-edge.sbs" ascii wide
        $stats = "/stats/salo/monitor.php" ascii wide
    condition:
        3 of them
}

rule Salo_Hotfix_Delivery_Package {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects the Salo Hotfix delivery package structure - legitimate pythonw.exe with trojanized Python libs"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $dir_pattern = "release-hotfix" ascii wide
        $version_dir = "9.48.13" ascii wide
        $pdb_path = "D:\\a\\1\\b\\bin\\amd64\\pythonw.pdb" ascii wide
        $locks_dir = ".locks" ascii wide
    condition:
        ($dir_pattern and $version_dir) or ($pdb_path and $dir_pattern)
}

rule Salo_Hotfix_XOR_Key_In_Memory {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects XOR decryption key used in Salo Hotfix campaign in process memory"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $key = "o6utydhcgf75ks" ascii wide
        $func = "reduceShowData" ascii
        $domain = "shitrba" ascii wide
        $c2 = "burning-edge" ascii wide
    condition:
        $key or ($func and any of ($domain,$c2))
}
rule Kortex_RAT_PKG_Binary {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects Kortex RAT - Node.js RAT packed with Vercel pkg, uses GitHub Gist dead-drop for C2 resolution"
        hash = "bf3af0269374ac1312e4a478480678a8f5988a206e1f150fe54cd07e77fdf5a8"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        
    strings:
        $pkg_marker1 = "C:\\snapshot\\Builder\\client.js" ascii
        $pkg_marker2 = "kortex-client" ascii
        $pkg_marker3 = "Kortex Background Node" ascii
        $pkg_build = "pkg . --targets node18-win-x64 --output dist/svchost.exe" ascii
        
        $gist_url = "gist.githubusercontent.com/HexReaper" ascii
        $gist_id = "eec6869214d2b4e12bd606529128f8c2" ascii
        
        $dep_screenshot = "screenshot-desktop" ascii
        $dep_ws = "\"ws\":" ascii
        $dep_nedb = "\"nedb\":" ascii
        $dep_admzip = "\"adm-zip\":" ascii
        $dep_sqlite = "\"sqlite3\":" ascii
        
        $node_ver = "Node.js JavaScript Runtime" ascii
        $node_18 = { 46 69 6C 65 56 65 72 73 69 6F 6E 00 00 00 31 38 2E 35 2E 30 } // FileVersion 18.5.0
        
    condition:
        uint16(0) == 0x5A4D and
        filesize > 40MB and filesize < 60MB and
        (
            (any of ($pkg_marker*)) or
            ($gist_url) or
            ($gist_id) or
            (3 of ($dep_*) and $node_ver)
        )
}

rule Kortex_RAT_MSI_Dropper {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects Kortex RAT MSI dropper - trojanized Element 3D installer"
        hash = "455bf1be7ee17e25e99054d04f83c512b1f4c886f3ce2868831b7c04d9635392"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        
    strings:
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        
        $product1 = "System Service" ascii wide
        $product2 = "SystemService_8436" ascii wide
        $action = "cmd.exe /c start /b svchost.exe" ascii wide
        $upgrade = "{9054E078-8F0D-435A-9A8C-7B7261229952}" ascii wide
        $product_code = "{FE8E87C3-3A2E-4970-9371-ECEF23F3C5BC}" ascii wide
        
    condition:
        $msi_magic at 0 and
        filesize > 10MB and filesize < 25MB and
        (
            ($action) or
            ($product1 and $product2) or
            (any of ($upgrade, $product_code))
        )
}

rule Kortex_RAT_WebSocket_C2_Config {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects Kortex RAT C2 configuration patterns in Node.js PKG binaries"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        
    strings:
        $ws_c2_1 = "ws://2.27.28.167:6062" ascii
        $ws_c2_2 = "ws://144.31.84.211:6062" ascii
        $ws_c2_3 = "ws://83.217.208.72:6062" ascii
        $gist = "HexReaper" ascii
        $port = ":6062" ascii
        
    condition:
        any of ($ws_c2_*) or
        ($gist and $port)
}
rule Riptide_Proxy_Server {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects Riptide proxy server binary based on embedded Go package paths and function names"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        investigation = "Operation Riptide"

    strings:
        $pkg1 = "riptide/internal/socketmanager" ascii
        $pkg2 = "riptide/internal/proxytunnel/upstream" ascii
        $pkg3 = "riptide/internal/handlers/http" ascii
        $pkg4 = "riptide/internal/handlers/socks5" ascii
        $pkg5 = "riptide/internal/upstreamselector" ascii
        $pkg6 = "riptide/internal/acl/keystore" ascii
        $pkg7 = "riptide/pkg/clickhouse" ascii
        $pkg8 = "riptide/pkg/distlimit" ascii
        $pkg9 = "riptide/pkg/throttler" ascii
        $pkg10 = "riptide/internal/tracker" ascii
        $pkg11 = "riptide/internal/ipallocator" ascii
        $pkg12 = "riptide/pkg/dnscache" ascii

        $func1 = "handleConnection" ascii
        $func2 = "HandleRequestUpstream" ascii
        $func3 = "dialViaSocks5" ascii
        $func4 = "bidirectionalDataCopy" ascii
        $func5 = "StartBandwidthReporter" ascii
        $func6 = "cleanupExpiredSessionIPs" ascii

        $dev_path = "riptide-main/" ascii

    condition:
        (3 of ($pkg*)) or (2 of ($pkg*) and 2 of ($func*)) or ($dev_path and 2 of ($pkg*))
}

rule Riptide_Proxy_Server_Kompiuteris_Build {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects Riptide proxy binary compiled by 'Kompiuteris' developer"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        investigation = "Operation Riptide"

    strings:
        $dev = "C:/Users/Kompiuteris/" ascii wide
        $tg = "Telegram Desktop/riptide-main/" ascii wide
        $riptide = "riptide/internal/" ascii

    condition:
        ($dev or $tg) and $riptide
}

rule Subway_Kount_Session_Generator {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects Subway Kount Session Generator credential stuffing tool"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        investigation = "Operation Riptide"

    strings:
        $name = "Subway Kount Session Generator" ascii wide
        $client_id = "efeb9bea-106d-4a27-acb4-c171474d4dda" ascii wide
        $tenant = "02d64b66-5494-461d-8e0d-5c72dc1efa7f" ascii wide
        $redirect = "subway-mobile-app://auth/" ascii wide
        $adobe_org = "D793BF115757EDD37F000101@AdobeOrg" ascii wide
        $msal = "MSAL.iOS" ascii wide
        $b2c = "b2c_1a_signin_mobile" ascii wide

    condition:
        $name or ($client_id and $tenant) or (3 of them)
}
rule NKFZ5966_DOCX_Lure {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects NKFZ5966 Boeing RFQ spear-phishing DOCX lure documents with embedded RTF via aFChunk"
        hash1 = "6ad6c38552304b963d6a53e77078c6741cbebf52e758716c470be92c79805cb4"
        hash2 = "20cff974367eed6e5b208d69ed49e7a9f50afbeeb60cf2f23a3a2e4ca3f1e08c"
        hash3 = "b7077463eec3d4107f1fcaa7a00847f0921f38ce018221b553e06c1861458ee2"
        tlp = "WHITE"
        campaign = "NKFZ5966PURCHASE"
    strings:
        $afchunk = "aFChunk" ascii
        $rtf_ext = ".rtf" ascii
        $creator = "Christian Booc" ascii wide
        $modifier = "John" ascii wide
        $pk = { 50 4B 03 04 }
    condition:
        $pk at 0 and $afchunk and $rtf_ext and ($creator or $modifier)
}

rule NKFZ5966_JS_Dropper {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects JavaScript droppers from NKFZ5966 campaign using tZaVLLetjJ separator deobfuscation"
        hash1 = "2927bd11ed8d3fbadf7cb3960edf1cd30d1cf515853cb9c0fcad42fabce745d8"
        hash2 = "b0e20b5136c9d7ee37bb7c9e044e46f4a29049038ec3543156c1e84c7bd6f062"
        tlp = "WHITE"
        campaign = "NKFZ5966PURCHASE"
    strings:
        $sep = "tZaVLLetjJ" ascii
        $split = ".split(" ascii
        $join = ".join(" ascii
        $wmi = "winmgmts" ascii nocase
        $ax = "ActiveXObject" ascii
        $ws = "WScript" ascii nocase
    condition:
        filesize < 200KB and $sep and $split and $join and ($wmi or $ax or $ws)
}

rule NKFZ5966_Protected_Py {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects Protected.py Python RAT loader from NKFZ5966 campaign"
        hash = "2f515997ab1c7f5ab94a46041ad2af06031a842469b65bcbd2c64bd47f12a896"
        tlp = "WHITE"
        campaign = "NKFZ5966PURCHASE"
    strings:
        $s1 = "_spIvxmOlxyrRncug6XRQAZJvHjaRUHpp" ascii
        $s2 = "_builtin_" ascii
        $s3 = "_cCLe6QapwlMP8dRyovJTvEJF64KqGx5G" ascii
        $s4 = "Checksum mismatch" ascii
        $import = "from _builtin_ import" ascii
        $rot13 = "(_b - 65 + 13) % 26 + 65" ascii
        $xor = "b ^ key for b in data" ascii
    condition:
        filesize < 100KB and 3 of them
}

rule NKFZ5966_Builtin_Module {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects _builtin_.py helper module from NKFZ5966 campaign"
        tlp = "WHITE"
        campaign = "NKFZ5966PURCHASE"
    strings:
        $s1 = "_6pMj2TM6H4wqQlq3mTD2wlnMTRXIOjoM" ascii
        $s2 = "_cCLe6QapwlMP8dRyovJTvEJF64KqGx5G" ascii
        $s3 = "_ccle6qapwlmp8dryovjtvejf64kqgx5g" ascii
        $builtins = "_builtins" ascii
    condition:
        filesize < 10KB and 2 of them
}

rule NKFZ5966_PS1_Downloader {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects PowerShell downloader stage from NKFZ5966 campaign"
        hash = "bba584c9c26bfe14083256f4f2ec9ea6bcf12db3cf7e1b7424f90fccced508be"
        tlp = "WHITE"
        campaign = "NKFZ5966PURCHASE"
    strings:
        $s1 = "python312x64.zip" ascii wide
        $s2 = "Protected.py" ascii wide
        $s3 = "pythonw.exe" ascii wide
        $s4 = "CallByName" ascii wide
        $s5 = "filemail.com" ascii wide nocase
        $s6 = "Templates" ascii wide
    condition:
        3 of them
}

rule NKFZ5966_License_PDF_Encrypted_DLL {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects the encrypted DLL payload disguised as license.pdf"
        hash = "d3e13175378035d36ff5e568748e1b063f4216e077516ffa79683ddb43ed7524"
        tlp = "WHITE"
        campaign = "NKFZ5966PURCHASE"
    strings:
        $not_pdf = { 25 50 44 46 }
    condition:
        filesize > 500KB and filesize < 1MB and not $not_pdf at 0 and
        for any i in (0..3) : (uint8(i) != 0x00)
}
rule ClearFake_GoGarble_idpagent_DLL {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "ClearFake delivery payload - Go/garble DLL masquerading as Logitech idpagent"
        hash = "4a1af31f881671df1ee3d4c3e8c0aa07c1da4aaf8142849543b80962c56839f1"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech/post/clearfake-aerovector-webdav"
    strings:
        $manifest1 = "LogitechInternationalS.A..idpagent" ascii wide
        $export1 = "ServiceMain" ascii
        $gogarble1 = "oCwEoKC." ascii
        $gogarble2 = "jJ1jzqMS." ascii
        $gogarble3 = "v0iKwwugAtzu." ascii
        $gogarble4 = "jt4ew64." ascii
        $gogarble5 = "dL_hhnqj." ascii
        $gogarble6 = "hLKYl7k5nwVB." ascii
        $goruntime = "handler.GOMAXPROCS" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize > 5MB and filesize < 10MB and
        (
            ($manifest1 and $export1) or
            (3 of ($gogarble*) and $goruntime) or
            ($manifest1 and any of ($gogarble*))
        )
}

rule ClearFake_GoGarble_strprov_DLL {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "ClearFake delivery payload - Go/garble DLL masquerading as Intel strprov"
        hash = "4d22efd2ea58e7643c5b6b82143c8978de7102356346fe4f5357807268cbad5d"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech/post/clearfake-aerovector-webdav"
    strings:
        $manifest1 = "IntelCorporation.strprov" ascii wide
        $export1 = "WppGetRegistryAsync" ascii
        $gogarble1 = "LIfGHEXe." ascii
        $gogarble2 = "uan7vKDbNNLZ." ascii
        $gogarble3 = "zuAxJaomfjtW." ascii
        $gogarble4 = "lBFYJ69aASm." ascii
        $gogarble5 = "FQjmTk." ascii
        $gogarble6 = "pPToNEZdU." ascii
        $embedded_hash = "5f566b8060af5dcf2bb32599f0d90d9b6c002cd445f22159b86edf45e23a5dae" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize > 3MB and filesize < 8MB and
        (
            ($manifest1 and $export1) or
            (3 of ($gogarble*)) or
            ($manifest1 and any of ($gogarble*)) or
            $embedded_hash
        )
}

rule ClearFake_GoGarble_Generic_Masquerade {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Generic detection for Go/garble DLLs masquerading as vendor components via PE manifest"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech/post/clearfake-aerovector-webdav"
    strings:
        $go_runtime1 = "handler.GOMAXPROCS" ascii
        $go_runtime2 = "handler.Gosched" ascii
        $go_runtime3 = "handler.LockOSThread" ascii
        $go_runtime4 = "handler.SetFinalizer" ascii
        $masq_logitech = "LogitechInternationalS.A." ascii
        $masq_intel = "IntelCorporation." ascii
        $svc_main = "ServiceMain" ascii
        $garble_sync = "sync/atomic." ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize > 2MB and filesize < 15MB and
        2 of ($go_runtime*) and
        $garble_sync and
        (
            $masq_logitech or
            $masq_intel or
            ($svc_main and 2 of ($go_runtime*))
        )
}

rule ClearFake_WebDAV_HTML_Lure {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "ClearFake HTML lure page mimicking Cloudflare phishing interstitial"
        hash = "4e4b991e3f39a37ded079c9e0089d7c06ed2d8c5cd907b7af72e7fa78c726e4f"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech/post/clearfake-aerovector-webdav"
    strings:
        $title = "Suspected phishing site | Cloudflare" ascii
        $bypass = "/cdn-cgi/phish-bypass" ascii
        $turnstile = "challenges.cloudflare.com/turnstile" ascii
        $sitekey = "0x4AAAAAABDaGKKSGLylJZFA" ascii
        $typo = "werification.google" ascii
        $bypass_btn = "Ignore & Proceed" ascii
    condition:
        filesize > 3KB and filesize < 10MB and
        3 of them
}
import "pe"
import "math"

rule SilverFox_ValleyRAT_Qt_Dropper {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "SilverFox/ValleyRAT Qt framework dropper with win64_protection obfuscation"
        tlp = "WHITE"
        hash1 = "c709ed855b596e46c4df8eb3ff6d50ca55869ae9deb59e04a49fd2df31f77c71"
        hash2 = "7f707cb02409b31b80cf4428fbc882cde513e20d105391b8cec298940579e23b"
        reference = "https://intel.breakglass.tech"
    strings:
        $rtti1 = ".?AVQCoreApplication@@" ascii
        $rtti2 = ".?AVQAbstractEventDispatcher@@" ascii
        $rtti3 = "control_flow_flattener@win64_protection" ascii
        $rtti4 = ".?AVQBig5Codec@@" ascii
        $api1 = "WSAAsyncSelect" ascii
        $api2 = "NtQueryInformationProcess" ascii
        $api3 = "NtRemoveProcessDebug" ascii
        $api4 = "DbgUiSetThreadDebugObject" ascii
        $api5 = "CreateWellKnownSid" ascii
        $ver1 = "KrGQrMWIYYBu" ascii wide
        $ver2 = "QUuGdbsRjD" ascii wide
        $ver3 = "WdiyvdJiY" ascii wide
        $ver4 = "STXZcW" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize > 1MB and filesize < 30MB and
        $rtti3 and
        2 of ($rtti1, $rtti2, $rtti4) and
        2 of ($api*)
}

rule SilverFox_Gh0stRAT_CFG_Variant {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "SilverFox Gh0stRAT variant with win64_protection control flow flattening and TLS anti-debug"
        tlp = "WHITE"
        hash = "a1a0f35f0ac483a6c5649f6fa338952c2d2c457d2cb1b2fcef16bdc96fdfdb8b"
        reference = "https://intel.breakglass.tech"
    strings:
        $rtti1 = "control_flow_flattener@win64_protection" ascii
        $rtti2 = "execute_flattened" ascii
        $func1 = "GetBuf@@YAPEAXXZ" ascii
        $func2 = "TimerInit@@YAXXZ" ascii
        $api1 = "NtQueryInformationProcess" ascii
        $api2 = "NtRemoveProcessDebug" ascii
        $api3 = "DbgUiSetThreadDebugObject" ascii
        $api4 = "CreateProcessAsUserW" ascii
        $api5 = "CreateWellKnownSid" ascii
        $cmd = "cmd.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize > 200KB and filesize < 2MB and
        $rtti1 and
        1 of ($func*) and
        3 of ($api*) and
        pe.number_of_sections >= 6
}

rule SilverFox_RustyStealer_Launcher {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "SilverFox RustyStealer Rust-based launcher with hex-encoded encrypted payload and persistence name pool"
        tlp = "WHITE"
        hash = "74edf6950c62bc4cfbaeb1a101316f231ca010cc9777d2e42d46a174cbdac598"
        reference = "https://intel.breakglass.tech"
    strings:
        $pdb = "launcher.pdb" ascii
        $rust1 = "C:\\Users\\dev\\.cargo\\" ascii
        $rust2 = "/rustc/" ascii
        $persist1 = "SystemLauncher.exe" ascii
        $persist2 = "CloudAssistant.exe" ascii
        $persist3 = "SecurityScanner.exe" ascii
        $persist4 = "ServiceController.exe" ascii
        $persist5 = "PrivacyGuardian.exe" ascii
        $persist6 = "AutoUpdater.exe" ascii
        $persist7 = "DiskOptimizer.exe" ascii
        $persist8 = "FileManager.exe" ascii
        $persist9 = "ResourceMonitor.exe" ascii
        $persist10 = "DevToolkit.exe" ascii
        $api = "BCryptGenRandom" ascii
        $path = "ProgramData" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize > 5MB and filesize < 25MB and
        ($pdb or $rust1) and
        4 of ($persist*) and
        $api and
        $path and
        math.entropy(0, filesize) > 5.0
}

rule SilverFox_Win64Protection_Generic {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Generic detection for win64_protection control flow flattening obfuscator used by SilverFox campaign"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $cfg1 = "control_flow_flattener@win64_protection" ascii
        $cfg2 = "execute_flattened" ascii
        $anti1 = "NtQueryInformationProcess" ascii
        $anti2 = "NtRemoveProcessDebug" ascii
        $anti3 = "DbgUiSetThreadDebugObject" ascii
    condition:
        uint16(0) == 0x5A4D and
        $cfg1 and
        ($cfg2 or 2 of ($anti*))
}

rule SilverFox_Persistence_Names {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects SilverFox persistence executable name pool used for masquerading"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $p1 = "SystemLauncher.exe" ascii wide
        $p2 = "FileManager.exe" ascii wide
        $p3 = "CloudAssistant.exe" ascii wide
        $p4 = "DataExplorer.exe" ascii wide
        $p5 = "ImageViewer.exe" ascii wide
        $p6 = "ResourceMonitor.exe" ascii wide
        $p7 = "AutoUpdater.exe" ascii wide
        $p8 = "DiskOptimizer.exe" ascii wide
        $p9 = "SecurityScanner.exe" ascii wide
        $p10 = "PowerUtility.exe" ascii wide
        $p11 = "TaskHelper.exe" ascii wide
        $p12 = "DevToolkit.exe" ascii wide
        $p13 = "AdminConsole.exe" ascii wide
        $p14 = "EventHandler.exe" ascii wide
        $p15 = "MediaProcessor.exe" ascii wide
        $p16 = "JobScheduler.exe" ascii wide
        $p17 = "AppInstaller.exe" ascii wide
        $p18 = "PrivacyGuardian.exe" ascii wide
        $p19 = "DesktopCompanion.exe" ascii wide
        $p20 = "ServiceController.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        6 of ($p*)
}
/*
    SheetRAT Detection Rules
    Author: GHOST - Breakglass Intelligence
    Date: 2026-03-31
    Reference: https://intel.breakglass.tech/
    TLP: WHITE
*/

rule SheetRAT_Client_PDB {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SheetRAT client via developer PDB path"
        hash = "e98a790eb7a81cb9243128d3eff6767ede03715a0d732dafee1fce76a1a15264"
        tlp = "WHITE"
        family = "SheetRAT"
    strings:
        $pdb = "Sheet rat" ascii wide nocase
        $pdb2 = "SheetRat" ascii wide nocase
        $pdb3 = "\\Backdoor\\Sheet rat" ascii wide
        $pdb4 = "\\hack tool\\Backdoor\\" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and any of them
}

rule SheetRAT_Client_Imphash {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SheetRAT client builds via shared imphash"
        hash = "e98a790eb7a81cb9243128d3eff6767ede03715a0d732dafee1fce76a1a15264"
        tlp = "WHITE"
        family = "SheetRAT"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
}

rule SheetRAT_Client_Strings {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SheetRAT client via characteristic .NET method names and strings"
        hash = "e98a790eb7a81cb9243128d3eff6767ede03715a0d732dafee1fce76a1a15264"
        tlp = "WHITE"
        family = "SheetRAT"
    strings:
        // .NET method names (present in #Strings heap, not obfuscated)
        $m1 = "StartAsBypass" ascii
        $m2 = "LoopInstall" ascii
        $m3 = "ScreenShot" ascii wide
        $m4 = "GetFiltes" ascii  // Note: typo in original code ("Filtes" not "Files")
        $m5 = "AntiDefender" ascii
        $m6 = "InstallWatchDog" ascii
        $m7 = "MutexControl" ascii
        $m8 = "DataInstall" ascii

        // Plugin system
        $p1 = "Plugin.Plugin" wide

        // Assembly metadata
        $a1 = "a7805e28-c8db-482c-8b04-06c0ca884f7d" ascii  // Assembly GUID
        $a2 = "vnrelhhbkamt" ascii  // Obfuscated namespace (sample-specific)

        // Characteristic string patterns (plaintext in #Strings)
        $s1 = "FriendlyName" wide
        $s2 = "NtProtectVirtualMemory" ascii
        $s3 = "GetForegroundWindow" ascii
        $s4 = "CreateToolhelp32Snapshot" ascii
        $s5 = "Process32First" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            (3 of ($m*)) or
            ($p1 and 2 of ($m*)) or
            ($a1) or
            (4 of ($s*) and any of ($m*))
        )
}

rule SheetRAT_Client_Behavioral {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SheetRAT client via behavioral string combination (works across cipher variants)"
        hash = "e98a790eb7a81cb9243128d3eff6767ede03715a0d732dafee1fce76a1a15264"
        tlp = "WHITE"
        family = "SheetRAT"
    strings:
        // These appear in the #Strings heap (method/type names) and survive obfuscation
        $func1 = "StartAsBypass" ascii
        $func2 = "LoopInstall" ascii
        $func3 = "ScreenShot" ascii
        $func4 = "GetFiltes" ascii  // Distinctive typo unique to SheetRAT
        $func5 = "AntiDefender" ascii

        // Win32 API imports (always present)
        $api1 = "NtProtectVirtualMemory" ascii
        $api2 = "GetModuleHandleA" ascii
        $api3 = "Process32First" ascii
        $api4 = "GetForegroundWindow" ascii
        $api5 = "VirtualProtect" ascii

        // .NET markers
        $net1 = "v4.0.30319" ascii
        $net2 = "#Strings" ascii
        $net3 = "#US" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        all of ($net*) and
        3 of ($func*) and
        2 of ($api*)
}

rule SheetRAT_Builder_Server {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SheetRAT builder/server executable"
        tlp = "WHITE"
        family = "SheetRAT"
    strings:
        $s1 = "ConfigBulid" ascii wide  // Note: typo "Bulid" is in original code
        $s2 = "INSTALLWATCHDOG" ascii wide
        $s3 = "ANTIPROCESS" ascii wide
        $s4 = "ANTIVIRTUAL" ascii wide
        $s5 = "NAMECLIENT" ascii wide
        $s6 = "NAMEWATCHDOG" ascii wide
        $s7 = "SigTheif" ascii wide  // Note: typo "Theif" is in original code
        $s8 = "PUMPER" ascii wide
        $s9 = "HKCUNAME" ascii wide
        $s10 = "TASKWATCHDOGNAME" ascii wide
        $s11 = "PROXYSTRING" ascii wide
        $s12 = "CTRLJUMP" ascii wide
        $s13 = "JUNKCODE" ascii wide
        $s14 = "ARITHNMETIC" ascii wide  // Note: typo in original code
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        6 of them
}

rule SheetRAT_Plugin_Stealer {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SheetRAT Stealer plugin DLL"
        tlp = "WHITE"
        family = "SheetRAT"
    strings:
        $s1 = "Stealer" ascii wide
        $s2 = "Plugin" ascii wide
        $s3 = "Chromium" ascii wide
        $s4 = "Login Data" ascii wide
        $s5 = "Web Data" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        all of them
}

rule SheetRAT_Pinggy_C2 {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects binaries containing Pinggy tunnel C2 references"
        tlp = "WHITE"
        family = "SheetRAT"
    strings:
        $pinggy1 = "pinggy.link" ascii wide nocase
        $pinggy2 = "free.pinggy" ascii wide nocase
        $pinggy3 = ".a.free.pinggy" ascii wide nocase
        // UTF-16LE encoded (for .NET user strings)
        $pinggy4 = { 70 00 69 00 6E 00 67 00 67 00 79 00 }  // "pinggy" UTF-16LE
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        any of ($pinggy*)
}

rule VENON_Banker_Rust_DLL {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects VENON banking trojan - Rust-based Brazilian banker distributed as trojanized libcef.dll"
        hash1 = "dc7c8f5cb67148876617f387df095dcea8598726fe5599cc1d3bab18932d372d"
        hash2 = "530e501f3e0aa8a5e3a41a06b0ba4e159ea6cea258b71c644c0578b856aebddb"
        hash3 = "00dbe21b176bef396455459d7e8da3365397a47c9c54b4422a30f8dae7cb578b"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
        
    strings:
        $venon1 = "VENON_BLOCK_START" ascii
        $venon2 = "VENON_BLOCK_END" ascii
        $venon3 = "VENON_HOST" ascii
        $venon4 = "VENON_PORT" ascii
        $venon5 = "VENON_TLS" ascii
        $venon6 = "VENON_PHONE_FORM" ascii
        
        $module1 = "src\\pixswap.rs" ascii
        $module2 = "src\\boletoswap.rs" ascii
        $module3 = "src\\clipswap.rs" ascii
        $module4 = "src\\site_block.rs" ascii
        $module5 = "src\\config\\remote.rs" ascii
        $module6 = "src\\stealth\\indirect_syscall.rs" ascii
        
        $debug1 = "[PIXSWAP]" ascii
        $debug2 = "[CLIPSWAP]" ascii
        $debug3 = "[BLOCK24H]" ascii
        $debug4 = "[STEALTH]" ascii
        $debug5 = "[CONFIG]" ascii
        $debug6 = "[DCOMP]" ascii
        $debug7 = "[TELE]" ascii
        
        $persist1 = "NVIDIA Notification Service" ascii wide
        $persist2 = "NVIDIAFilter" ascii wide
        $persist3 = "NVIDIAConsumer" ascii wide
        $persist4 = "NVIDIANotification.exe" ascii wide
        
        $bank1 = "BR.GOV.BCB.PIX" ascii
        $bank2 = "BOLETOCONTA" ascii
        $bank3 = "Banco do Brasil" ascii
        $bank4 = "bankline.itau.com" ascii
        
        $cargo = "C:\\cargobr\\" ascii
        
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and (
            2 of ($venon*) or
            3 of ($module*) or
            (2 of ($debug*) and 1 of ($persist*)) or
            ($cargo and 1 of ($bank*)) or
            (1 of ($venon*) and 1 of ($module*) and 1 of ($bank*))
        )
}

rule VENON_Banker_Behavioral {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects VENON banker behavioral patterns - PIX/boleto/crypto swap"
        tlp = "WHITE"
        
    strings:
        $pix1 = "[PIXSWAP] PIX detected" ascii
        $pix2 = "[PIXSWAP] EMV orig_key" ascii
        $pix3 = "000201BR.GOV.BCB.PIX" ascii
        
        $boleto1 = "[BOLETOSWAP]" ascii
        $boleto2 = "BOLETOCONTA" ascii
        
        $crypto1 = "BTCETHLTCDOGETRX" ascii
        $crypto2 = "BinanceCoinbaseKrakenKuCoin" ascii
        $crypto3 = "MetaMaskTrustPhantomLedger" ascii
        
        $stealth1 = "ntdll unhook OK" ascii
        $stealth2 = "indirect syscalls OK" ascii
        $stealth3 = "ETW patch OK" ascii
        $stealth4 = "AMSI bypass OK" ascii
        
        $ws1 = "[WS] Auth OK" ascii
        $ws2 = "[WS] Conectando host" ascii
        
    condition:
        uint16(0) == 0x5A4D and (
            2 of ($pix*) or
            (1 of ($boleto*) and 1 of ($crypto*)) or
            3 of ($stealth*) or
            (1 of ($ws*) and (1 of ($pix*) or 1 of ($crypto*)))
        )
}

rule VENON_Banker_CEF_Sideload {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects trojanized libcef.dll used by VENON banker for DLL sideloading"
        tlp = "WHITE"
        
    strings:
        $export1 = "cef_initialize" ascii
        $export2 = "cef_execute_process" ascii
        $export3 = "WryCheckWebView2" ascii
        $export4 = "WryTestWindow" ascii
        $export5 = "RelaunchChromeBrowserWithNewCommandLineIfNeeded" ascii
        
        $mal1 = "VENON_" ascii
        $mal2 = "pixswap" ascii
        $mal3 = "boletoswap" ascii
        $mal4 = "clipswap" ascii
        $mal5 = "NVIDIANotification" ascii
        $mal6 = "fetch_remote_host" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        3 of ($export*) and
        2 of ($mal*)
}
/*
 * GlassWorm Wave 3 -- Infrastructure and Network Detection Rules
 * Breakglass Intelligence -- GHOST
 * Date: 2026-03-31
 * Reference: https://intel.breakglass.tech
 *
 * These rules complement the binary detection rules from tipo_deincognito's
 * Codeberg analysis by adding network traffic and infrastructure indicators.
 */

rule glassworm_stage1_stego_decoder {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "GlassWorm Wave 3 Stage 1 -- Unicode variation selector steganography decoder pattern"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
        tlp = "WHITE"

    strings:
        // Unicode variation selector range used for steganography
        $stego_range = /\\u[eE]01[0-9a-fA-F]{2}/ ascii
        // AES-256-CBC decryption pattern
        $aes_decrypt = "aes-256-cbc" ascii nocase
        // Solana RPC endpoint queries
        $solana_rpc1 = "api.mainnet-beta.solana.com" ascii
        $solana_rpc2 = "getSignaturesForAddress" ascii
        // Known shared auth token
        $partner_token = "mulKRsVtolooY8S" ascii
        // Init file pattern
        $init_json = "init.json" ascii
        // 2-day cooldown check
        $cooldown = /Date\.now\(\)\s*-\s*\d+\s*\*\s*24\s*\*\s*60\s*\*\s*60\s*\*\s*1000/ ascii

    condition:
        filesize < 1MB and 3 of them
}

rule glassworm_rat_v2 {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "GlassWorm Wave 3 RAT v2.x -- Socket.IO C2 client with SOCKS proxy capability"
        hash = "41caca39e0605527f6124e18902b8719131b1e13531fa5b71da4020ea6b9e1a7"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
        tlp = "WHITE"

    strings:
        // Socket.IO connection parameters
        $socketio_partner = "_partner" ascii
        $socketio_platform = "\"platform\"" ascii
        $socketio_uuid = "\"uuid\"" ascii
        // C2 command types
        $cmd_socks = "start_socks" ascii
        $cmd_stop = "stop_socks" ascii
        $cmd_command = "\"command\"" ascii
        $cmd_version = "check_version" ascii
        // Known error file patterns
        $err_file1 = "XkrnQlLAX" ascii
        $err_file2 = "error_ws" ascii
        // wrtc module path
        $wrtc = "/module/wrtc" ascii
        // Signal handlers for resilience
        $sig1 = "SIGINT" ascii
        $sig2 = "SIGTERM" ascii
        $sig3 = "SIGUSR2" ascii
        // Error handler endpoint
        $error_handler = "/error-handler" ascii
        // Reconnection parameters
        $reconnect = /reconnectionAttempts.*20/ ascii

    condition:
        filesize < 5MB and 4 of them
}

rule glassworm_stealer_stage3 {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "GlassWorm Wave 3 Stage 3 -- Multi-path credential stealer (AppleScript + Node.js)"
        hash = "d72c1c75958ad7c68ef2fb2480fa9ebe185e457f3b62047b31565857fa06a51a"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
        tlp = "WHITE"

    strings:
        // AppleScript credential harvesting
        $applescript1 = "security find-generic-password" ascii
        $applescript2 = "Application wants to install helper" ascii
        // Wallet targeting
        $wallet_dir1 = "Ledger Live" ascii
        $wallet_dir2 = "Trezor Suite" ascii
        $wallet_dir3 = "Electrum" ascii
        // GitHub/NPM token theft
        $git_cred = "git credential fill" ascii
        $npm_token = ".npmrc" ascii
        $github_token = "GITHUB_TOKEN" ascii
        // Exfil endpoints
        $exfil_p2p = "/p2p" ascii
        $exfil_wall = "/wall" ascii
        // Russian language artifacts
        $russian1 = {D0 A2 D0 BE D0 BA D0 B5 D0 BD} // "Токен" (Token)
        $russian2 = {D0 9D D0 B5 D0 B2 D0 B0 D0 BB D0 B8 D0 B4 D0 BD D1 8B D0 B9} // "Невалидный" (Invalid)
        // Campaign metadata
        $campaign_uuid = "7c102363-8542-459f-95dd-d845ec5df44c" ascii
        // Quarantine stripping (trojanized wallets)
        $xattr = "xattr -rc" ascii
        // Keychain password store
        $keychain_store = "pass_users_for_script" ascii

    condition:
        filesize < 5MB and 4 of them
}

rule glassworm_solana_c2_resolver {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "GlassWorm Solana blockchain C2 address resolution -- queries wallet memos for C2 IP"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
        tlp = "WHITE"

    strings:
        // GlassWorm C2 wallet address
        $wallet = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii
        // Funder wallet
        $funder = "G2YxRa6wt1qePMwfJzdXZG62ej4qaTC7YURzuh2Lwd3t" ascii
        // Solana RPC methods used
        $method1 = "getSignaturesForAddress" ascii
        $method2 = "getTransaction" ascii
        // Memo field extraction
        $memo = "\"memo\"" ascii
        // Base64 link decoding
        $link = "\"link\"" ascii
        // BitTorrent DHT as backup
        $dht_key = "ea1b4260a83348243387d6cdfda3cd287e323958" ascii

    condition:
        filesize < 2MB and ($wallet or $funder or $dht_key) and 1 of ($method*, $memo, $link)
}

rule glassworm_c2_payload_delivery {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "GlassWorm Wave 3 C2 HTTP payload delivery -- Base64 encoded paths with AES key headers"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
        tlp = "WHITE"

    strings:
        // Known payload delivery URL path patterns
        $path1 = "/get_arhive_npm/" ascii
        $path2 = "/get_encrypt_file_exe/" ascii
        $path3 = "/env/" ascii
        $path4 = "/darwin-universal/" ascii
        $path5 = "/module/wrtc" ascii
        // AES key delivery headers
        $header1 = "secretkey" ascii
        $header2 = "ivbase64" ascii
        // Rate limit headers from C2
        $ratelimit = "x-ratelimit-limit" ascii
        // Base64-encoded kill switch
        $killswitch = "cHJvY2Vzcy5leGl0KDAp" ascii  // process.exit(0)

    condition:
        filesize < 1MB and 2 of them
}

rule glassworm_launchagent_persistence {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "GlassWorm Wave 3 macOS persistence -- LaunchAgent with hidden Node.js"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
        tlp = "WHITE"

    strings:
        $plist = "com.user.nodestart" ascii
        $hidden_node = ".config/system/.data/.nodejs" ascii
        $node_version = "node-v23.5.0-darwin" ascii
        $webrtc_module = ".nodejs/webrtc/index.js" ascii
        $keepalive = "SuccessfulExit" ascii

    condition:
        2 of them
}
import "pe"

rule LofyGang_NYX_Stealer_npm_Package {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects LofyGang NYX Stealer npm package (XOR-encrypted payload)"
        hash = "bad0fd9a966e4eb7edfaa7e19da025f9be3c1541de22b5ca76afb9afbc0b548f"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $xor_key = "qA#s5~d/YLcg5c;^r7$x" ascii
        $wrapper1 = "const _k=" ascii
        $wrapper2 = "_d=Buffer.from(" ascii
        $wrapper3 = "new Function(\"require\"" ascii
        $wrapper4 = "_r[_i]=_d[_i]^_k.charCodeAt" ascii
    condition:
        $xor_key or (2 of ($wrapper*))
}

rule LofyGang_NYX_Stealer_Decrypted_Payload {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects decrypted LofyGang NYX Stealer JavaScript payload"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $id1 = "=== Lofygang Started ===" ascii
        $id2 = "lofygang-local" ascii
        $id3 = "Lofygang | t.me/lofygang" ascii
        $id4 = "GrabberLofy" ascii
        $c2 = "ws://18.231.131.246" ascii
        $nyx1 = "_NYX_HIDDEN" ascii
        $nyx2 = "_nyx_launch.vbs" ascii
        $func1 = "ScreenLiveClient" ascii
        $func2 = "SKIBIDI_INJ" ascii
        $func3 = "InputPayload" ascii
        $func4 = "dQw4w9WgXcQ:" ascii
        $func5 = "downloadAndRunExe" ascii
        $func6 = "collectAllTokens" ascii
        $func7 = "extractAllWallets" ascii
        $dropper = "chromelevator.exe" ascii
        $domain = "amoboobs.com" ascii
    condition:
        3 of them
}

rule LofyGang_ChromeElevator_Stealer {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects LofyGang chromelevator.exe native stealer"
        hash = "d6090c843c58f183fb5ed3ab3f67c9d96186d1b30dfd9927b438ff6ffedee196"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $s1 = "COOKIES:" ascii
        $s2 = "PASSWORDS:" ascii
        $s3 = "TOKENS:" ascii
        $s4 = "MASTER_KEY:" ascii
        $s5 = "GrabBoundary7f3a9c" ascii
        $s6 = "Telegram: file sent successfully" ascii
        $s7 = "Webhook: could not open zip for upload" ascii
        $s8 = "Deriving runtime decryption keys" ascii
        $s9 = "__DLL_PIPE_COMPLETION_SIGNAL__" ascii
        $s10 = "Memory protection set to PAGE_EXECUTE_READ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 4 of ($s*)
}

rule LofyGang_npm_Maintainer_Pattern {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects npm packages by known LofyGang maintainer account"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $email = "duba70015@gmail.com" ascii
        $maintainer = "consolelofy" ascii
        $pkg1 = "separadordeinfocc" ascii
        $pkg2 = "undicy-http" ascii
    condition:
        any of them
}

rule LofyGang_Discord_Webhook_Exfil {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects LofyGang specific Discord webhook and Telegram exfiltration"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $webhook = "1484725829412851915" ascii
        $tg_bot = "8713069597:AAHVJGtP17y2cYnPAk8j0ro0fhuJuNP9Uak" ascii
        $tg_chat = "8245283894" ascii
        $steam_key = "440D7F4D810EF9298D25EDDF37C1F902" ascii
    condition:
        any of them
}
import "pe"

rule SERPENTINE_KISS_Loader {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects KISS Loader (so.py) used in SERPENTINE#CLOUD German Wave campaign"
        hash = "5cab6bf65f7836371d5c27fbfc20fe10c0c4a11784990ed1a3d2585fa5431ba6"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"

    strings:
        $s1 = "KISS Loader" ascii
        $s2 = "Early Bird APC Injection" ascii
        $s3 = "EarlyBirdInjector" ascii
        $s4 = "QueueUserAPC" ascii
        $s5 = "xor_decrypt" ascii
        $s6 = "load_key" ascii
        $s7 = "CreateProcessW" ascii
        $s8 = "PurePythonObfuscator" ascii

    condition:
        4 of them
}

rule SERPENTINE_PurePythonObfuscator_Key {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects PurePythonObfuscator JSON key files used in SERPENTINE#CLOUD"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"

    strings:
        $j1 = "PurePythonObfuscator" ascii
        $j2 = "xor_key" ascii
        $j3 = "entropy_source" ascii
        $j4 = "secrets+urandom+time+pid" ascii
        $j5 = "sha3_256" ascii

    condition:
        3 of them
}

rule SERPENTINE_German_Wave_LNK {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects LNK files from SERPENTINE#CLOUD German Wave (ec2amaz-t08m3l3 build env)"
        hash = "85123630e0931cc73e435b3c73f1b006c78ffad8740cbb3f3aa0db0a933cf77c"
        tlp = "WHITE"

    strings:
        $machine = "ec2amaz-t08m3l3" ascii wide
        $tunnel = "trycloudflare.com" ascii wide
        $wsh = "brown.wsh" ascii wide
        $path = "DavWWWRoot" ascii wide

    condition:
        uint32(0) == 0x0000004c and 2 of them
}

rule SERPENTINE_German_Wave_JobBat {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects job.bat dropper from SERPENTINE#CLOUD German Wave"
        hash = "329c639007c6a2d3ae76bc7a19bfda829c63898d1541234bd50a68f42cf08916"
        tlp = "WHITE"

    strings:
        $s1 = "ihk.de" ascii nocase
        $s2 = "raise.zip" ascii
        $s3 = "so.py" ascii
        $s4 = "fraps.bin" ascii
        $s5 = "frexs.bin" ascii
        $s6 = "trycloudflare.com" ascii
        $s7 = "revive.bat" ascii
        $s8 = "python-3.10.0-embed" ascii

    condition:
        4 of them
}

rule SERPENTINE_dcRAT_Payload {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects dcRAT payload from SERPENTINE#CLOUD German Wave (fraps.bin decrypted)"
        hash = "0e3b61878f50b78c5b28b9c9d2067c3c157e23c163a48dc346555ad61d992f96"
        tlp = "WHITE"

    strings:
        $dcrat = "DcRatByqwqdanchun" ascii wide
        $patchetw = "PatchETW" ascii wide
        $patchmem = "PatchMem" ascii wide
        $amsi1 = "x64_am_si_patch" ascii wide
        $amsi2 = "x86_am_si_patch" ascii wide
        $etw1 = "x64_etw_patch" ascii wide
        $etw2 = "x86_etw_patch" ascii wide
        $detect1 = "DetectSandboxie" ascii wide
        $detect2 = "DetectManufacturer" ascii wide
        $detect3 = "DetectDebugger" ascii wide
        $c2_1 = "Aes256" ascii wide
        $c2_2 = "masterKey" ascii wide
        $c2_3 = "Server_Certificate" ascii wide
        $c2_4 = "ActivatePo_ng" ascii wide
        $c2_5 = "Pac_ket" ascii wide

    condition:
        pe.is_32bit() and $dcrat and 4 of ($patchetw, $patchmem, $amsi*, $etw*, $detect*, $c2_*)
}

rule SERPENTINE_XenoRAT_Payload {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects XenoRAT payload from SERPENTINE#CLOUD German Wave (frexs.bin decrypted)"
        hash = "e149f0e26afa5460ac5a9aac3688495ae7cb4642c8ec6e5f40ac63e0bafae00c"
        tlp = "WHITE"

    strings:
        $xeno1 = "xeno rat client" ascii wide
        $xeno2 = "xeno_rat_client" ascii wide
        $xeno3 = "Xeno_rat_nd8912d" ascii wide
        $xeno4 = "XenoManager" ascii wide
        $xeno5 = "XenoUpdateManager" ascii wide
        $handler1 = "Type0Receive" ascii wide
        $handler2 = "Type1Receive" ascii wide
        $handler3 = "Type2Receive" ascii wide
        $net1 = "ConnectSubSockAsync" ascii wide
        $net2 = "ConnectAndSetupAsync" ascii wide

    condition:
        pe.is_32bit() and 3 of ($xeno*) and 1 of ($handler*) and 1 of ($net*)
}

rule SERPENTINE_Donut_Custom_Variant {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects custom Donut shellcode variant used in SERPENTINE#CLOUD (23925-byte loader)"
        tlp = "WHITE"

    strings:
        // Entry point: CALL delta + POP RCX + XOR EAX,EAX + JS
        $entry = { E8 ?? ?? ?? ?? 59 31 C0 48 0F 88 }
        // Donut module DLL loading strings in decrypted instance
        $dll1 = "ole32.dll" ascii
        $dll2 = "oleaut32.dll" ascii
        $dll3 = "wininet.dll" ascii
        $dll4 = "mscoree.dll" ascii
        // AMSI/WLDP bypass strings
        $amsi = "AmsiScanBuffer" ascii
        $wldp = "WldpQueryDynamicCodeTrust" ascii

    condition:
        $entry at 0 and 2 of ($dll*) and ($amsi or $wldp)
}
rule Trojanized_ZKM_ResourceMonitor {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects trojanized Zelix KlassMaster obfuscator with ResourceMonitor RAT payload using DoH-based C2"
        hash = "cb574adcec44a9b051269d23bd4567b876253c068c3b30835ff38aec85d49d55"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $manifest_zkm = "Main-Class: com.zelix.ZKM" ascii
        $class_rm = "com/zelix/ResourceMonitor" ascii
        $source_patch = "PatchSystem.java" ascii
        $crack_leaks = "leaks.tf" ascii wide
        $drop_qt = "qtshadercache-x86_64-little_endian-llp64" ascii wide
        $drop_jar = "874643384254.jar" ascii wide
        $task_name = "MicrosoftEdgeUpdateTaskMachineOA" ascii wide
        $doh_url = "cloudflare-dns.com/dns-query" ascii wide
        $doh_ct = "application/dns-message" ascii wide
        $c2_domain = "download.launcher.mcleaks.de" ascii
        $xor_key = "pt9T;c8" ascii
    condition:
        uint16(0) == 0x504B and  // ZIP/JAR magic
        filesize > 5MB and filesize < 20MB and
        ($manifest_zkm and $class_rm) or
        ($source_patch and any of ($drop_*)) or
        ($doh_url and $doh_ct and $c2_domain) or
        3 of ($drop_qt, $drop_jar, $task_name, $crack_leaks, $xor_key)
}

rule MCLeaks_DoH_RAT_Generic {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects Java RAT using DNS-over-HTTPS to cloudflare-dns.com for C2 resolution"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $doh1 = "cloudflare-dns.com" ascii wide
        $doh2 = "dns-query" ascii wide
        $doh3 = "application/dns-message" ascii wide
        $java1 = "URLClassLoader" ascii
        $java2 = "loadClass" ascii
        $java3 = "getManifest" ascii
        $java4 = "Main-Class" ascii
        $java5 = "ProcessBuilder" ascii
        $mcleaks = "mcleaks" ascii wide nocase
    condition:
        (uint16(0) == 0x504B or uint32(0) == 0xCAFEBABE) and
        2 of ($doh*) and
        2 of ($java*) and
        $mcleaks
}

rule ResourceMonitor_PatchSystem_Dropper {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-04-01"
        description = "Detects ResourceMonitor/PatchSystem Java dropper class"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $source = "PatchSystem.java" ascii
        $class = "ResourceMonitor" ascii
        $method1 = "schtasks" ascii wide
        $method2 = "javaw.exe" ascii wide
        $method3 = "CREATE_NEW" ascii
        $method4 = "SecretKeySpec" ascii
        $method5 = "URLClassLoader" ascii
        $drop1 = "874643384254" ascii wide
        $drop2 = "qtshadercache" ascii wide
    condition:
        uint32(0) == 0xCAFEBABE and  // Java class magic
        $source and
        ($class or 2 of ($method*) or any of ($drop*))
}
rule SumUp_PhishKit_LoginPage {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SumUp phishing kit login page (Live Control Panel Premium)"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $title = "SUMUP - LOGIN" ascii wide nocase
        $form_action = "send.php" ascii
        $challenge = "challenge" ascii
        $locale = "locale" ascii
        $css_nonce = "cvkPNRgHn87c8elY" ascii
        $sumup_svg = "M22.171.19H1.943" ascii
        $panel_path = "../panel/classes/processor.php" ascii
        $redirect_targets = "login.php?e" ascii
        $keepalive = "keepAlive" ascii
        $redirect_listener = "redirectionListener" ascii
        $clear_redirect = "clearRedirection" ascii
    condition:
        3 of them
}

rule SumUp_PhishKit_AdminPanel {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SumUp phishing kit admin panel (Live Control Panel Premium)"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $panel_title = "Live Control Panel Premium" ascii
        $victim_control = "CONTROL VICTIM" ascii
        $victim_ip = "Victim IP address" ascii
        $bot_token_field = "Telegram Bot Token" ascii
        $block_pc = "Block pc devices" ascii
        $shutdown = "Shut down" ascii
        $page_redirect = "pageID" ascii
        $vic_ip = "vicIP" ascii
        $darija1 = "kaysaynk" ascii
        $darija2 = "mchaaa" ascii
    condition:
        3 of them
}

rule SumUp_PhishKit_VictimView {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SumUp phishing kit victim control view page"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $redirect_fn = "function redirect(page)" ascii
        $victim_data = "getVictimData" ascii
        $current_page = "CURRENT PAGE" ascii
        $redirects = "REDIRECTS" ascii
        $victim_logs = "VICTIM LOGS" ascii
        $login_error = "LOGIN ERROR" ascii
        $sms_error = "SMS ERROR" ascii
        $email_error = "EMAIL ERROR" ascii
        $neon_green = "#39FF14" ascii
        $panel_footer = "Live Control Panel Premium" ascii
    condition:
        4 of them
}

rule SumUp_PhishKit_OTP_Page {
    meta:
        author = "GHOST - Breakglass Intelligence"
        date = "2026-03-31"
        description = "Detects SumUp phishing kit SMS/Email OTP harvesting pages"
        tlp = "WHITE"
        reference = "https://intel.breakglass.tech"
    strings:
        $title_sms = "Authentication - SMS" ascii
        $title_email = "Authentication - EMAIL" ascii
        $otp_input = "otp_code_input_" ascii
        $sumup_brand = "SumUp" ascii
        $move_focus = "moveFocus" ascii
        $one_time_code = "one-time-code" ascii
        $panel_processor = "../panel/classes/processor.php" ascii
        $css_nonce = "cvkPNRgHn87c8elY" ascii
    condition:
        4 of them
}
