/*
 * Breakglass Intelligence - Consolidated YARA Rules
 * Generated: 2026-04-01T20:46:56.864Z
 * Source: https://intel.breakglass.tech
 * Total unique rules: 103
 *
 * These rules are derived from GHOST Intelligence investigations.
 * For per-investigation rules, see the individual investigation directories.
 */

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
        description = "Detects PurePythonObfuscator JSON key files used in SERPENTINE#CLOUD"
        $j1 = "PurePythonObfuscator" ascii
        $j2 = "xor_key" ascii
        $j3 = "entropy_source" ascii
        $j4 = "secrets+urandom+time+pid" ascii
        $j5 = "sha3_256" ascii
        3 of them
rule SERPENTINE_German_Wave_LNK {
        description = "Detects LNK files from SERPENTINE#CLOUD German Wave (ec2amaz-t08m3l3 build env)"
        hash = "85123630e0931cc73e435b3c73f1b006c78ffad8740cbb3f3aa0db0a933cf77c"
        $machine = "ec2amaz-t08m3l3" ascii wide
        $tunnel = "trycloudflare.com" ascii wide
        $wsh = "brown.wsh" ascii wide
        $path = "DavWWWRoot" ascii wide
        uint32(0) == 0x0000004c and 2 of them
rule SERPENTINE_German_Wave_JobBat {
        description = "Detects job.bat dropper from SERPENTINE#CLOUD German Wave"
        hash = "329c639007c6a2d3ae76bc7a19bfda829c63898d1541234bd50a68f42cf08916"
        $s1 = "ihk.de" ascii nocase
        $s2 = "raise.zip" ascii
        $s3 = "so.py" ascii
        $s4 = "fraps.bin" ascii
        $s5 = "frexs.bin" ascii
        $s6 = "trycloudflare.com" ascii
        $s7 = "revive.bat" ascii
        $s8 = "python-3.10.0-embed" ascii
rule SERPENTINE_dcRAT_Payload {
        description = "Detects dcRAT payload from SERPENTINE#CLOUD German Wave (fraps.bin decrypted)"
        hash = "0e3b61878f50b78c5b28b9c9d2067c3c157e23c163a48dc346555ad61d992f96"
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
        pe.is_32bit() and $dcrat and 4 of ($patchetw, $patchmem, $amsi*, $etw*, $detect*, $c2_*)
rule SERPENTINE_XenoRAT_Payload {
        description = "Detects XenoRAT payload from SERPENTINE#CLOUD German Wave (frexs.bin decrypted)"
        hash = "e149f0e26afa5460ac5a9aac3688495ae7cb4642c8ec6e5f40ac63e0bafae00c"
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
        pe.is_32bit() and 3 of ($xeno*) and 1 of ($handler*) and 1 of ($net*)
rule SERPENTINE_Donut_Custom_Variant {
        description = "Detects custom Donut shellcode variant used in SERPENTINE#CLOUD (23925-byte loader)"
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
        $entry at 0 and 2 of ($dll*) and ($amsi or $wldp)
rule PlugX_VqqSpeedDl_Loader {
        date = "2026-03-31"
        description = "Detects PlugX Type II DLL sideloading loader masquerading as Tencent QQ VqqSpeedDl.dll"
        hash = "216989f56970e3ea045773224e82b2afe78ed29e49df7d044d5a5992d622d881"
        malware_family = "PlugX"
        threat_actor = "Mustang Panda"
        $export1 = "_RigsterHook@0" ascii
        $export2 = "_UnRigsterHook@0" ascii
        $com_clsid = "{AF6C6F71-5822-463A-8CA1-EA496D0CA2C7}" ascii wide
        $com_typelib = "{25BD9BB7-33EC-4220-B725-56C470146288}" ascii wide
        $dll_name1 = "VqqSpeedDl.DLL" ascii wide
        $dll_name2 = "VqqSpeedDl.VqqDownload" ascii wide
        $dll_name3 = "585276.dll" ascii
        $midl = "MIDL version 6.00.0366" ascii
        $method1 = "method SetHttpSpeedWWW" ascii
        $method2 = "method StartHttpWW" ascii
        $method3 = "method SetLoadDllInfoW" ascii
        $method4 = "method COMSetHttpSpeed" ascii
        $delphi = "Embarcadero RAD Studio" ascii
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($export1 and $export2) or
            ($com_clsid) or
            ($com_typelib) or
            ($dll_name1 and 2 of ($method*)) or
            ($dll_name3 and $export1) or
            ($dll_name2 and $delphi and $midl)
        )
rule PlugX_RigsterHook_Export {
        description = "Detects PlugX loader DLLs with the characteristic _RigsterHook misspelling in exports"
        $rigster = "_RigsterHook" ascii
        $unrigster = "_UnRigsterHook" ascii
        $mz = "MZ"
        $mz at 0 and
        filesize < 5MB and
        ($rigster or $unrigster)
rule PlugX_TypeII_Loader_Generic {
        description = "Generic detection for PlugX Type II DLL sideloading loaders with COM registration and dynamic API resolution"
        $api1 = "GetModuleHandleA" ascii
        $api2 = "GetProcAddress" ascii
        $api3 = "CreateProcessA" ascii
        $api4 = "GetModuleFileNameA" ascii
        $api5 = "CreateToolhelp32Snapshot" ascii
        $api6 = "Process32First" ascii
        $api7 = "Process32Next" ascii
        $api8 = "VirtualAlloc" ascii
        $com1 = "InprocServer32" ascii wide
        $com2 = "CLSID" ascii wide
        $com3 = "AppID" ascii wide
        $delphi_marker = { 66 62 3A 43 2B 2B 48 4F 4F 4B }
        5 of ($api*) and
        2 of ($com*) and
        $delphi_marker
rule PlugX_Imphash_551af7f2 {
        description = "Detects PlugX loader by imphash (VqqSpeedDl variant, March 2026)"
        pe.imphash() == "551af7f202e2768c63b16f27eadd2d27"
rule Salo_Hotfix_Trojanized_Aliases_Py {
        description = "Detects trojanized Python encodings/aliases.py used in Salo Hotfix campaign. The legitimate aliases.py is modified to include obfuscated command execution via os.system()."
        hash = "0ab588411764cc47f270ca775b90afd8ae5981d118256e18a7b9c4f48e0abeeb"
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
        $header and $import_os and 4 of ($type_*,$global_region,$mem_protect,$ram_protect,$conhost,$os_system)
rule Salo_Hotfix_PowerShell_Stage {
        description = "Detects the /salo PowerShell payload with XOR-encrypted stage and junk variable obfuscation"
        hash = "bec7c3a4a90d107dd1f19024e44bd77a7ce87344dd68950d6f269855c1ff0f92"
        $xor_key = "o6utydhcgf75ks" ascii wide
        $func_name = "reduceShowData" ascii
        $byte_array = "[Byte[]]$useByteArray" ascii
        $exec_pattern = "scriptblock]::Create($decryptedCode)" ascii
        $junk_var = "Get-AzSubscription -Append -TaskPath" ascii
        2 of them
rule Salo_Hotfix_Decrypted_Injector {
        description = "Detects the decrypted Stage 2 payload containing AMSI bypass and process hollowing code"
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
rule Salo_Hotfix_Delivery_Package {
        description = "Detects the Salo Hotfix delivery package structure - legitimate pythonw.exe with trojanized Python libs"
        $dir_pattern = "release-hotfix" ascii wide
        $version_dir = "9.48.13" ascii wide
        $pdb_path = "D:\\a\\1\\b\\bin\\amd64\\pythonw.pdb" ascii wide
        $locks_dir = ".locks" ascii wide
        ($dir_pattern and $version_dir) or ($pdb_path and $dir_pattern)
rule Salo_Hotfix_XOR_Key_In_Memory {
        description = "Detects XOR decryption key used in Salo Hotfix campaign in process memory"
        $key = "o6utydhcgf75ks" ascii wide
        $func = "reduceShowData" ascii
        $domain = "shitrba" ascii wide
        $c2 = "burning-edge" ascii wide
        $key or ($func and any of ($domain,$c2))
rule glassworm_stage1_stego_decoder {
        description = "GlassWorm Wave 3 Stage 1 -- Unicode variation selector steganography decoder pattern"
        reference = "https://codeberg.org/tip-o-deincognito/glassworm-writeup"
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
        filesize < 1MB and 3 of them
rule glassworm_rat_v2 {
        description = "GlassWorm Wave 3 RAT v2.x -- Socket.IO C2 client with SOCKS proxy capability"
        hash = "41caca39e0605527f6124e18902b8719131b1e13531fa5b71da4020ea6b9e1a7"
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
        filesize < 5MB and 4 of them
rule glassworm_stealer_stage3 {
        description = "GlassWorm Wave 3 Stage 3 -- Multi-path credential stealer (AppleScript + Node.js)"
        hash = "d72c1c75958ad7c68ef2fb2480fa9ebe185e457f3b62047b31565857fa06a51a"
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
rule glassworm_solana_c2_resolver {
        description = "GlassWorm Solana blockchain C2 address resolution -- queries wallet memos for C2 IP"
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
        filesize < 2MB and ($wallet or $funder or $dht_key) and 1 of ($method*, $memo, $link)
rule glassworm_c2_payload_delivery {
        description = "GlassWorm Wave 3 C2 HTTP payload delivery -- Base64 encoded paths with AES key headers"
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
        filesize < 1MB and 2 of them
rule glassworm_launchagent_persistence {
        description = "GlassWorm Wave 3 macOS persistence -- LaunchAgent with hidden Node.js"
        $plist = "com.user.nodestart" ascii
        $hidden_node = ".config/system/.data/.nodejs" ascii
        $node_version = "node-v23.5.0-darwin" ascii
        $webrtc_module = ".nodejs/webrtc/index.js" ascii
        $keepalive = "SuccessfulExit" ascii
rule InvisibleFerret_BeaverTail_ShellDropper {
        description = "Detects BeaverTail/InvisibleFerret shell script droppers used in DPRK Contagious Interview campaign"
        hash1 = "9bc46c59e734b2389328a5103739f42bed7d820c73f75c49cc5a2e8cacfe8940"
        hash2 = "e224a1db42ae2164d6b2f2a7f1f0e02056e099fc8d669ce37cdaa0a2a2750e3b"
        hash3 = "65665c3faba4fbfed12488e945306b10131afb9d3ad928accdcef75e0945a086"
        hash4 = "247fdba5fbfd076d9c530d937406aa097d6794b9af26bfc64bf6ea765ed51a50"
        $github_repo = "RominaMabelRamirez/dify" ascii
        $branch = "refs/heads/bai/api" ascii
        $myvars = "source ~/.myvars" ascii
        $mypaswor = "MY_PASWOR" ascii
        $x64nvidia = "x64nvidia" ascii
        $payuniversal = "payuniversal" ascii
        $nvidiasdk = "nvidiasdk.fly.dev" ascii
        $linvidia = ".linvidia" ascii
        $downx64 = "downx64" ascii
        $n3_dir = "/.n3/" ascii
        $npc_marker = "/.npc" ascii
        $pawr_endpoint = "/pawr/" ascii
        $ua_205 = "-A 205" ascii
        $ua_206 = "-A 206" ascii
        $ua_207 = "-A 207" ascii
        $ua_209 = "\"209\"" ascii
        $nvm_install = "nvm install 20.19.0" ascii
        filesize < 5KB and 3 of them
rule InvisibleFerret_VBS_Dropper {
        description = "Detects InvisibleFerret VBScript dropper that uses renamed 7-Zip for extraction"
        hash = "6a16b1ef16e999a0d32a4b9189f6f179d629ba143b5b03db06c95156ee089615"
        $vscode_argv = ".vscode\\argv.exe" ascii wide
        $p8_archive = "p8.zi" ascii wide
        $nvidiasdk = "nvidiasdk" ascii wide
        $ppp_password = "-pppp" ascii wide
        $wscript_shell = "WScript.Shell" ascii wide
        $seven_zip_extract = "x \"\"\"" ascii wide
rule InvisibleFerret_JS_Payload {
        description = "Detects obfuscated InvisibleFerret/BeaverTail JavaScript payload"
        hash = "bf7a54cf4ded7a2de2607d2a18def5c518c8bd2b1e38606c15332745031bddf5"
        $json_cookie = "{\"cookie\":\"(function(" ascii
        $obf_pattern1 = "_0x5c8f7e" ascii
        $obf_pattern2 = "_0x4e9b02" ascii
        $obf_pattern3 = "_0x4f93" ascii
        $hex_func = "return _0x4f93(" ascii
        $parseInt_chain = "parseInt(_0x" ascii
        $push_shift = "['push'](_0x" ascii
        filesize < 200KB and ($json_cookie or (3 of ($obf_*) and $parseInt_chain))
rule InvisibleFerret_Stage3_Generic {
        description = "Detects InvisibleFerret Stage 3 compiled Python backdoor (generic indicators)"
        hash_linux = "699cd6c292b8a5933dabee63c74a9a3069ed6432c3433ab945ab46fe816d9e2c"
        hash_windows = "1c8c1a693209c310e9089eb2d5713dc00e8d19f335bde34c68f6e30bccfbe781"
        $nvidia_persist = "NvidiaDriverUpdate" ascii wide
        $avatar_plist = "com.avatar.update.wake.plist" ascii wide
        $queue_bat = "queue.bat" ascii wide
        $ssh_steal = ".ssh" ascii wide
        $aws_cred = ".aws/credentials" ascii wide
        $gcloud = ".config/gcloud" ascii wide
        $env_file = ".env" ascii wide
        $brave = "BraveSoftware" ascii wide
        $yandex = "YandexBrowser" ascii wide
        $chrome_login = "Login Data" ascii wide
        $pyinstaller = "PYZ-00.pyz" ascii
        $pyinstaller2 = "_MEIPASS" ascii
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize > 5MB and filesize < 15MB and
        (($pyinstaller or $pyinstaller2) and 3 of ($nvidia_persist, $avatar_plist, $queue_bat, $ssh_steal, $aws_cred, $gcloud, $env_file, $brave, $yandex, $chrome_login))
rule InvisibleFerret_C2_Domains {
        description = "Detects InvisibleFerret/Contagious Interview C2 domain references"
        $d1 = "videodriverzone.cloud" ascii wide nocase
        $d2 = "videotechdrivers.cloud" ascii wide nocase
        $d3 = "driversnap.cloud" ascii wide nocase
        $d4 = "camdriverstore.cloud" ascii wide nocase
        $d5 = "driverstream.cloud" ascii wide nocase
        $d6 = "nvidiasdk.fly.dev" ascii wide nocase
        any of them
rule ContagiousInterview_NVIDIA_Masquerade {
        description = "Detects DPRK Contagious Interview campaign NVIDIA masquerade patterns"
        $nvidiasdk_exe = "nvidiasdk.exe" ascii wide nocase
        $x64nvidia = "x64nvidia" ascii wide nocase
        $nvidia_zip = "NVIDIA.zip" ascii wide nocase
        $nvidia_tar = "nvidia.tar.gz" ascii wide nocase
        $nvidiasdk_path = "\\nvidiasdk\\" ascii wide
        $nvidia_run_key = "NvidiaDriverUpdate" ascii wide
        $c2_ip1 = "95.216.37.186" ascii wide
        $c2_ip2 = "95.164.17.24" ascii wide
        $c2_ip3 = "45.59.163.23" ascii wide
        $c2_ip4 = "172.86.93.139" ascii wide
        2 of ($nvidiasdk_*, $x64nvidia, $nvidia_zip, $nvidia_tar, $linvidia, $nvidia_run_key) or
        2 of ($c2_ip*)
rule SERPENTINE_CLOUD_Loader_DLL {
        description = "Detects SERPENTINE#CLOUD Mingw-w64 loader DLLs (loader_N.dll) used for process injection into explorer.exe"
        hash1 = "b2fa2988c6ad45276eaf737416fafb8328d90a452eff47f5ca5b9770f87c87bd"
        hash2 = "ce0a323ff6a3988f8550144bde76dfd250fcae689c73ce319e31c3006fc78b19"
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
        filesize < 50KB and
        $export and
        $target and
        $loader_pattern and
        $compiler and
        4 of ($api*) and
        $mingw
rule SERPENTINE_CLOUD_Encrypted_Payload {
        description = "Detects SERPENTINE#CLOUD encrypted own.enc payloads (16-byte XOR key prefix + Donut shellcode)"
        hash1 = "7ad06185c4f8d97db51b93d21aa9888ff21b9688b195fdaf6e3770a995e8d1a5"
        hash2 = "fe29f7972f68cf98c2a88cf43d68fea8695c55b56bb1fb7acc4d1eed8d732ed3"
        // After 16-byte XOR decryption, Donut shellcode starts with CALL +large_offset
        // The XOR pattern creates distinctive byte patterns
        // We match on file size (84070 bytes exactly for this wave) and high entropy
        $not_pe = { 4D 5A }
        not $not_pe at 0 and
        filesize == 84070 and
        // High entropy check via absence of long null runs
        not uint32(0) == 0x00000000 and
        not uint32(4) == 0x00000000
rule SERPENTINE_CLOUD_Donut_Shellcode {
        description = "Detects decrypted SERPENTINE#CLOUD Donut shellcode (CALL+POP pattern with instance structure)"
        hash1 = "746e42de473b3f78f64eb65e7b3468874f881219b7445d6648dcfc15f5489a5c"
        hash2 = "b25f0c7becfa5ea8e97c06a612f87e3802d953782ece6d69b2c43804b939c276"
        // CALL +0x113c0 followed by data
        $call_pattern = { E8 C0 13 01 00 }
        // Donut decoder stub: POP RCX; AND RSP,-10; PUSH RCX
        $decoder_stub = { 59 48 83 E4 F0 51 }
        // Process injection pattern at specific offset
        $inject_pattern = { 33 FF 48 8B D9 39 B9 38 02 00 00 }
        $call_pattern at 0 and
        ($decoder_stub or $inject_pattern)
rule SERPENTINE_CLOUD_Dropper_BAT {
        description = "Detects SERPENTINE#CLOUD stage 1 dropper BAT with WebDAV delivery and dual injection"
        hash = "ad888d6ba84ba839ebc1a0a9d5e4cca030c2b58624af828cdc932624e1ba73b4"
        $dav = "trycloudflare.com@SSL\\DavWWWRoot" ascii nocase
        $svc = "net start WebClient" ascii nocase
        $rundll = "rundll32.exe" ascii nocase
        $run_export = ",Run" ascii
        $startup = "WindowsSecurityHealth.bat" ascii
        $lock = "wupd.lock" ascii
        $callback = "/s/!ID!/" ascii
        $self_delete = "del \"%~f0\"" ascii nocase
        filesize < 10KB and
        $dav and
        $rundll and
        $run_export and
        3 of ($svc, $startup, $lock, $callback, $self_delete)
rule SERPENTINE_CLOUD_Inner_BAT_PEM_Payload {
        description = "Detects SERPENTINE#CLOUD inner BAT files with base64 payloads disguised as PEM certificates"
        hash1 = "deploy_2a1m0b.bat"
        hash2 = "configure_6t71fu.bat"
        $pem_begin = "-----BEGIN CERTIFICATE-----" ascii
        $pem_end = "-----END CERTIFICATE-----" ascii
        $certutil = "certutil -decode" ascii nocase
        $mz_b64 = "TVqQAAMAAAAEAAAA" ascii
        $bat_header = "@echo off" ascii nocase
        filesize > 100KB and
        filesize < 200KB and
        $bat_header and
        $pem_begin and
        $pem_end and
        $certutil and
        $mz_b64
rule SERPENTINE_CLOUD_Imphash_Cluster {
        description = "Detects PE files matching the SERPENTINE#CLOUD loader imphash cluster"
        pe.imphash() == "efd7f22fecb87f90fef74b8027a9ff28"
rule AndyVPN_Client_Windows {
        description = "Detects AndyVPN Windows client - Chinese GFW circumvention VPN with potential surveillance capabilities"
        hash = "02082547c01720f7bfbd8d2755482002370ea86473e7e2746d5e311b864f6041"
        family = "AndyVPN"
        type = "VPN Client / Potential Trojan"
        // SQL schema strings unique to AndyVPN
        $sql1 = "Create  TABLE softconfig([domain]" ascii
        $sql2 = "Create  TABLE vpnlist([id] INTEGER PRIMARY KEY" ascii
        $sql3 = "[tgddz] char(255)" ascii
        $sql4 = "[kefuHtml] text" ascii
        $sql5 = "[suidao] char(255)" ascii
        $sql6 = "[jiename] char(255)" ascii
        $sql7 = "[zzyanshi] int(10)" ascii
        // DuiLib Chinese UI framework
        $dui1 = "DuiLib" ascii
        $dui2 = "LibDui.dll" ascii
        // Login window class
        $login = "CLoginWnd::OnFinalMessage" ascii
        // QQ integration
        $qq = "wpa.qq.com/msgrd" ascii
        // VPN protocol markers
        $vpn1 = "shadowsocks" ascii
        $vpn2 = "RASAPI32.dll" ascii
        $vpn3 = "RasHangUpW" ascii
        // Crypto provider
        $crypto = "Microsoft Enhanced Cryptographic Provider v1.0" ascii
        (3 of ($sql*)) or
        ($login and $dui1 and 1 of ($vpn*)) or
        ($qq and $dui2 and $crypto)
rule AndyVPN_NSIS_Installer {
        description = "Detects NSIS installer packaging AndyVPN client"
        type = "Installer"
        $nsis = "Nullsoft Install System" ascii
        $vpn_exe = "andyvpn.exe" ascii wide
        $data_dat = "Data.dat" ascii wide
        $tap_driver = "tap0901.sys" ascii wide
        $libdui = "LibDui.dll" ascii wide
        $pac = ".pac" ascii wide
        $update = "update.exe" ascii wide
        filesize < 20MB and
        $nsis and
        $vpn_exe and
        3 of ($data_dat, $tap_driver, $libdui, $pac, $update)
rule ChainVPN_Mirror_Page {
        description = "Detects ChainVPN mirror landing page HTML"
        family = "ChainVPN"
        type = "Phishing/Distribution Page"
        $title = "ChainVPN" ascii nocase
        $chinese1 = {E5 85 A8 E7 BD 91 E6 9C 80 E8 89 AF E5 BF 83} // "全网最良心" UTF-8
        $js_host = "tj.wurugagu.com" ascii
        $baidu = "hm.baidu.com/hm.js" ascii
        $andyvpn = "andyvpn" ascii
        $v2ray = "V2Ray" ascii nocase
        $chain_desc = "Chain" ascii
        filesize < 500KB and
        ($title or $chinese1) and
        (2 of ($js_host, $baidu, $andyvpn, $v2ray))
rule AndyVPN_Panel_Response {
        description = "Detects AndyVPN panel HTML response"
        type = "C2 Panel"
        $title = "AndyVPN_" ascii
        $statics = "/statics/andy/" ascii
        $tg_php = "tg.php" ascii
        $unlock = {E8 A7 A3 E9 94 81 E6 97 A0 E9 99 90 E5 8F AF E8 83 BD} // "解锁无限可能" UTF-8
        $php_powered = "X-Powered-By: PHP/5.4" ascii
rule AndyVPN_Encrypted_SQLite_Config {
        description = "Detects encrypted Data.dat config file used by AndyVPN (encrypted SQLite)"
        hash_data_dat = "see investigation report"
        type = "Configuration"
        // Data.dat is encrypted, so we detect based on the parent installer or extraction context
        // This rule matches the andyvpn.exe binary that references the encrypted database
        $enc_error = "file is encrypted or is not a database" ascii
        $sql_schema1 = "softconfig" ascii
        $sql_schema2 = "vpnlist" ascii
        $sql_schema3 = "diqulist" ascii
        $crypto_provider = "Microsoft Enhanced Cryptographic Provider" ascii
        $enc_error and
        2 of ($sql_schema*) and
        $crypto_provider
rule SheetRAT_Client_PDB {
        description = "Detects SheetRAT client via developer PDB path"
        hash = "e98a790eb7a81cb9243128d3eff6767ede03715a0d732dafee1fce76a1a15264"
        family = "SheetRAT"
        $pdb = "Sheet rat" ascii wide nocase
        $pdb2 = "SheetRat" ascii wide nocase
        $pdb3 = "\\Backdoor\\Sheet rat" ascii wide
        $pdb4 = "\\hack tool\\Backdoor\\" ascii wide
        uint16(0) == 0x5A4D and filesize < 2MB and any of them
rule SheetRAT_Client_Imphash {
        description = "Detects SheetRAT client builds via shared imphash"
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
rule SheetRAT_Client_Strings {
        description = "Detects SheetRAT client via characteristic .NET method names and strings"
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
            (3 of ($m*)) or
            ($p1 and 2 of ($m*)) or
            ($a1) or
            (4 of ($s*) and any of ($m*))
rule SheetRAT_Client_Behavioral {
        description = "Detects SheetRAT client via behavioral string combination (works across cipher variants)"
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
        all of ($net*) and
        3 of ($func*) and
        2 of ($api*)
rule SheetRAT_Builder_Server {
        description = "Detects SheetRAT builder/server executable"
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
        filesize < 10MB and
        6 of them
rule SheetRAT_Plugin_Stealer {
        description = "Detects SheetRAT Stealer plugin DLL"
        $s1 = "Stealer" ascii wide
        $s2 = "Plugin" ascii wide
        $s3 = "Chromium" ascii wide
        $s4 = "Login Data" ascii wide
        $s5 = "Web Data" ascii wide
        filesize < 1MB and
        all of them
rule SheetRAT_Pinggy_C2 {
        description = "Detects binaries containing Pinggy tunnel C2 references"
        $pinggy1 = "pinggy.link" ascii wide nocase
        $pinggy2 = "free.pinggy" ascii wide nocase
        $pinggy3 = ".a.free.pinggy" ascii wide nocase
        // UTF-16LE encoded (for .NET user strings)
        $pinggy4 = { 70 00 69 00 6E 00 67 00 67 00 79 00 }  // "pinggy" UTF-16LE
        any of ($pinggy*)
rule Quasar_C2_znzglobalsol {
        description = "Detects Quasar RAT samples configured with znzglobalsol.com C2"
        $c2_domain = "znzglobalsol.com" ascii wide nocase
        $c2_remote = "remote.znzglobalsol.com" ascii wide nocase
        $c2_ip = "98.142.250.238" ascii wide
        $quasar_mutex1 = "QSR_MUTEX" ascii wide nocase
        $quasar_mutex2 = "Quasar" ascii wide nocase
        $port = "4782" ascii wide
        uint16(0) == 0x5A4D and filesize < 10MB and
        (any of ($c2_*) or (2 of ($quasar_*) and $c2_ip))
rule MeshAgent_znzglobalsol_C2 {
        description = "Detects MeshCentral agents configured to connect to znzglobalsol.com"
        $c2_url = "https://remote.znzglobalsol.com:8686/" ascii wide
        $c2_domain = "remote.znzglobalsol.com" ascii wide
        $c2_wss = "wss://98.142.250.238:8686" ascii wide
        $meshagent = "MeshAgent" ascii wide
        $meshservice_pdb = "MeshService64.pdb" ascii wide
        uint16(0) == 0x5A4D and filesize < 15MB and
        any of ($c2_*) and any of ($mesh*)
rule Quasar_Server_CA_Certificate {
        description = "Detects Quasar RAT Server CA self-signed certificate (specific instance)"
        $cert_cn = "Quasar Server CA" ascii
        $cert_serial = { E0 3C CB 7C 7E 1B 2F 54 AF A0 17 39 85 09 F5 }
        $cert_ski = { 16 38 03 D3 AB E0 34 4B 0F 9C 5E 40 3D 5D 4E F3 62 CD 07 E8 }
rule ClearFake_GoGarble_idpagent_DLL {
        description = "ClearFake delivery payload - Go/garble DLL masquerading as Logitech idpagent"
        hash = "4a1af31f881671df1ee3d4c3e8c0aa07c1da4aaf8142849543b80962c56839f1"
        reference = "https://intel.breakglass.tech/post/clearfake-aerovector-webdav"
        $manifest1 = "LogitechInternationalS.A..idpagent" ascii wide
        $export1 = "ServiceMain" ascii
        $gogarble1 = "oCwEoKC." ascii
        $gogarble2 = "jJ1jzqMS." ascii
        $gogarble3 = "v0iKwwugAtzu." ascii
        $gogarble4 = "jt4ew64." ascii
        $gogarble5 = "dL_hhnqj." ascii
        $gogarble6 = "hLKYl7k5nwVB." ascii
        $goruntime = "handler.GOMAXPROCS" ascii
        filesize > 5MB and filesize < 10MB and
            ($manifest1 and $export1) or
            (3 of ($gogarble*) and $goruntime) or
            ($manifest1 and any of ($gogarble*))
rule ClearFake_GoGarble_strprov_DLL {
        description = "ClearFake delivery payload - Go/garble DLL masquerading as Intel strprov"
        hash = "4d22efd2ea58e7643c5b6b82143c8978de7102356346fe4f5357807268cbad5d"
        $manifest1 = "IntelCorporation.strprov" ascii wide
        $export1 = "WppGetRegistryAsync" ascii
        $gogarble1 = "LIfGHEXe." ascii
        $gogarble2 = "uan7vKDbNNLZ." ascii
        $gogarble3 = "zuAxJaomfjtW." ascii
        $gogarble4 = "lBFYJ69aASm." ascii
        $gogarble5 = "FQjmTk." ascii
        $gogarble6 = "pPToNEZdU." ascii
        $embedded_hash = "5f566b8060af5dcf2bb32599f0d90d9b6c002cd445f22159b86edf45e23a5dae" ascii
        filesize > 3MB and filesize < 8MB and
            (3 of ($gogarble*)) or
            ($manifest1 and any of ($gogarble*)) or
            $embedded_hash
rule ClearFake_GoGarble_Generic_Masquerade {
        description = "Generic detection for Go/garble DLLs masquerading as vendor components via PE manifest"
        $go_runtime1 = "handler.GOMAXPROCS" ascii
        $go_runtime2 = "handler.Gosched" ascii
        $go_runtime3 = "handler.LockOSThread" ascii
        $go_runtime4 = "handler.SetFinalizer" ascii
        $masq_logitech = "LogitechInternationalS.A." ascii
        $masq_intel = "IntelCorporation." ascii
        $svc_main = "ServiceMain" ascii
        $garble_sync = "sync/atomic." ascii
        filesize > 2MB and filesize < 15MB and
        2 of ($go_runtime*) and
        $garble_sync and
            $masq_logitech or
            $masq_intel or
            ($svc_main and 2 of ($go_runtime*))
rule ClearFake_WebDAV_HTML_Lure {
        description = "ClearFake HTML lure page mimicking Cloudflare phishing interstitial"
        hash = "4e4b991e3f39a37ded079c9e0089d7c06ed2d8c5cd907b7af72e7fa78c726e4f"
        $title = "Suspected phishing site | Cloudflare" ascii
        $bypass = "/cdn-cgi/phish-bypass" ascii
        $turnstile = "challenges.cloudflare.com/turnstile" ascii
        $sitekey = "0x4AAAAAABDaGKKSGLylJZFA" ascii
        $typo = "werification.google" ascii
        $bypass_btn = "Ignore & Proceed" ascii
        filesize > 3KB and filesize < 10MB and
rule FloridaCambolaShop_Domain {
        description = "Detects references to floridacambolashop.com - suspicious pre-operational domain"
        confidence = "MEDIUM"
        $domain1 = "floridacambolashop.com" ascii wide nocase
        $domain2 = "floridacambolashop" ascii wide nocase
        $ip1 = "149.33.8.86" ascii wide
        $ipv6 = "2a0c:6741:0:1::99" ascii wide
rule FloridaCambolaShop_SSH_HostKey {
        description = "Detects SSH host key fingerprints associated with floridacambolashop.com server"
        $ed25519 = "IJWI4mSYkRm/9pAUt+FvaIZjALid+WleGFd6kS+ZD9nC" ascii
        $ecdsa = "BEBR97mPVqtAoeMzzRcxUfPpQ8Pqm0rJ7FVLNFPdtpTCqBob6ijceg5G4fbkeGF73K9E3507NKfgh95xkw6aeh8" ascii
rule SilverFox_ValleyRAT_Qt_Dropper {
        description = "SilverFox/ValleyRAT Qt framework dropper with win64_protection obfuscation"
        hash1 = "c709ed855b596e46c4df8eb3ff6d50ca55869ae9deb59e04a49fd2df31f77c71"
        hash2 = "7f707cb02409b31b80cf4428fbc882cde513e20d105391b8cec298940579e23b"
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
        filesize > 1MB and filesize < 30MB and
        $rtti3 and
        2 of ($rtti1, $rtti2, $rtti4) and
rule SilverFox_Gh0stRAT_CFG_Variant {
        description = "SilverFox Gh0stRAT variant with win64_protection control flow flattening and TLS anti-debug"
        hash = "a1a0f35f0ac483a6c5649f6fa338952c2d2c457d2cb1b2fcef16bdc96fdfdb8b"
        $rtti1 = "control_flow_flattener@win64_protection" ascii
        $rtti2 = "execute_flattened" ascii
        $func1 = "GetBuf@@YAPEAXXZ" ascii
        $func2 = "TimerInit@@YAXXZ" ascii
        $api1 = "NtQueryInformationProcess" ascii
        $api2 = "NtRemoveProcessDebug" ascii
        $api3 = "DbgUiSetThreadDebugObject" ascii
        $api4 = "CreateProcessAsUserW" ascii
        $cmd = "cmd.exe" ascii wide
        filesize > 200KB and filesize < 2MB and
        $rtti1 and
        1 of ($func*) and
        3 of ($api*) and
        pe.number_of_sections >= 6
rule SilverFox_RustyStealer_Launcher {
        description = "SilverFox RustyStealer Rust-based launcher with hex-encoded encrypted payload and persistence name pool"
        hash = "74edf6950c62bc4cfbaeb1a101316f231ca010cc9777d2e42d46a174cbdac598"
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
        filesize > 5MB and filesize < 25MB and
        ($pdb or $rust1) and
        4 of ($persist*) and
        $api and
        $path and
        math.entropy(0, filesize) > 5.0
rule SilverFox_Win64Protection_Generic {
        description = "Generic detection for win64_protection control flow flattening obfuscator used by SilverFox campaign"
        $cfg1 = "control_flow_flattener@win64_protection" ascii
        $cfg2 = "execute_flattened" ascii
        $anti1 = "NtQueryInformationProcess" ascii
        $anti2 = "NtRemoveProcessDebug" ascii
        $anti3 = "DbgUiSetThreadDebugObject" ascii
        $cfg1 and
        ($cfg2 or 2 of ($anti*))
rule SilverFox_Persistence_Names {
        description = "Detects SilverFox persistence executable name pool used for masquerading"
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
        6 of ($p*)
rule NKFZ5966_DOCX_Lure {
        description = "Detects NKFZ5966 Boeing RFQ spear-phishing DOCX lure documents with embedded RTF via aFChunk"
        hash1 = "6ad6c38552304b963d6a53e77078c6741cbebf52e758716c470be92c79805cb4"
        hash2 = "20cff974367eed6e5b208d69ed49e7a9f50afbeeb60cf2f23a3a2e4ca3f1e08c"
        hash3 = "b7077463eec3d4107f1fcaa7a00847f0921f38ce018221b553e06c1861458ee2"
        campaign = "NKFZ5966PURCHASE"
        $afchunk = "aFChunk" ascii
        $rtf_ext = ".rtf" ascii
        $creator = "Christian Booc" ascii wide
        $modifier = "John" ascii wide
        $pk = { 50 4B 03 04 }
        $pk at 0 and $afchunk and $rtf_ext and ($creator or $modifier)
rule NKFZ5966_JS_Dropper {
        description = "Detects JavaScript droppers from NKFZ5966 campaign using tZaVLLetjJ separator deobfuscation"
        hash1 = "2927bd11ed8d3fbadf7cb3960edf1cd30d1cf515853cb9c0fcad42fabce745d8"
        hash2 = "b0e20b5136c9d7ee37bb7c9e044e46f4a29049038ec3543156c1e84c7bd6f062"
        $sep = "tZaVLLetjJ" ascii
        $split = ".split(" ascii
        $join = ".join(" ascii
        $wmi = "winmgmts" ascii nocase
        $ax = "ActiveXObject" ascii
        $ws = "WScript" ascii nocase
        filesize < 200KB and $sep and $split and $join and ($wmi or $ax or $ws)
rule NKFZ5966_Protected_Py {
        description = "Detects Protected.py Python RAT loader from NKFZ5966 campaign"
        hash = "2f515997ab1c7f5ab94a46041ad2af06031a842469b65bcbd2c64bd47f12a896"
        $s1 = "_spIvxmOlxyrRncug6XRQAZJvHjaRUHpp" ascii
        $s2 = "_builtin_" ascii
        $s3 = "_cCLe6QapwlMP8dRyovJTvEJF64KqGx5G" ascii
        $s4 = "Checksum mismatch" ascii
        $import = "from _builtin_ import" ascii
        $rot13 = "(_b - 65 + 13) % 26 + 65" ascii
        $xor = "b ^ key for b in data" ascii
        filesize < 100KB and 3 of them
rule NKFZ5966_Builtin_Module {
        description = "Detects _builtin_.py helper module from NKFZ5966 campaign"
        $s1 = "_6pMj2TM6H4wqQlq3mTD2wlnMTRXIOjoM" ascii
        $s2 = "_cCLe6QapwlMP8dRyovJTvEJF64KqGx5G" ascii
        $s3 = "_ccle6qapwlmp8dryovjtvejf64kqgx5g" ascii
        $builtins = "_builtins" ascii
        filesize < 10KB and 2 of them
rule NKFZ5966_PS1_Downloader {
        description = "Detects PowerShell downloader stage from NKFZ5966 campaign"
        hash = "bba584c9c26bfe14083256f4f2ec9ea6bcf12db3cf7e1b7424f90fccced508be"
        $s1 = "python312x64.zip" ascii wide
        $s2 = "Protected.py" ascii wide
        $s3 = "pythonw.exe" ascii wide
        $s4 = "CallByName" ascii wide
        $s5 = "filemail.com" ascii wide nocase
        $s6 = "Templates" ascii wide
rule NKFZ5966_License_PDF_Encrypted_DLL {
        description = "Detects the encrypted DLL payload disguised as license.pdf"
        hash = "d3e13175378035d36ff5e568748e1b063f4216e077516ffa79683ddb43ed7524"
        $not_pdf = { 25 50 44 46 }
        filesize > 500KB and filesize < 1MB and not $not_pdf at 0 and
        for any i in (0..3) : (uint8(i) != 0x00)
rule NKFZ5966_ProtectedPy_Loader {
        description = "Detects the Protected.py obfuscated Python loader used in NKFZ5966 campaign"
        $deob_func = "_spIvxmOlxyrRncug6XRQAZJvHjaRUHpp" ascii
        $deob_chain = "base64.b64decode" ascii
        $xor_16 = "_xor_key = 16" ascii
        $builtin_import = "from _builtin_ import" ascii
        $memory_module = "memory.MemoryModule" ascii
        $license_pdf = "license.pdf" ascii
        $aes_import = "from Crypto.Cipher import AES" ascii
rule NKFZ5966_Builtin_Helper {
        description = "Detects the _builtin_.py helper module used in NKFZ5966 campaign"
        hash_parent = "2f515997ab1c7f5ab94a46041ad2af06031a842469b65bcbd2c64bd47f12a896"
        $class = "_cCLe6QapwlMP8dRyovJTvEJF64KqGx5G" ascii
        $xor_128 = "_xor_key = 128" ascii
        $checksum = "Checksum mismatch" ascii
        $getattr = "def __getattr__" ascii
rule NKFZ5966_Encrypted_DLL {
        description = "Detects the license.pdf encrypted DLL by header bytes"
        $header = { 16 13 ba 05 c2 83 ea 4f 34 a5 b1 33 be b7 a1 e3 }
        $header at 0 and filesize > 700000 and filesize < 800000
rule NKFZ5966_CS_Memory_DLL {
        description = "Detects the Cobalt Strike DLL with .nep section from NKFZ5966 campaign"
        hash = "d41757c87c22597f4d14406a356b50022cb9a6dcdd9baf0b7075d4fcff3bf774"
        $nep_section = ".nep" ascii
        $httpdnld = "httpdnld.cpp" ascii
        $persistappdata = "persistappdata.cpp" ascii
        $httpresource = "httpresource.cpp" ascii
        $createprocess = "create_process_server.cpp" ascii
        $httpdcserver = "httpdcserver.cpp" ascii
        $mz at 0 and $nep_section and 2 of ($http*, $persist*, $createprocess)
rule NKFZ5966_AES_Keys {
        description = "Detects NKFZ5966 campaign AES encryption keys in any file"
        $aes_key = { a3 4c 24 3e 8f ae 4a 20 ad 13 a0 e6 be 19 74 9c 9b 0b a4 7a c8 e7 9a f0 e4 da 57 f5 93 73 c0 03 }
        $aes_iv = { ad 4b 12 7c 68 3d 97 4d be ab 87 33 1b 86 48 84 }
        $aes_key_hex = "a34c243e8fae4a20ad13a0e6be19749c9b0ba47ac8e79af0e4da57f59373c003" ascii nocase
        $aes_iv_hex = "ad4b127c683d974dbeab87331b864884" ascii nocase
rule NKFZ5966_Persistence_Command {
        description = "Detects the specific persistence command from NKFZ5966 campaign"
        $persist = "SyncAppvPublishingServer.vbs" ascii wide
        $path = "python312x64" ascii wide
        $protected = "Protected.py" ascii wide
        $pythonw = "pythonw.exe" ascii wide
rule SumUp_PhishKit_LoginPage {
        description = "Detects SumUp phishing kit login page (Live Control Panel Premium)"
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
rule SumUp_PhishKit_AdminPanel {
        description = "Detects SumUp phishing kit admin panel (Live Control Panel Premium)"
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
rule SumUp_PhishKit_VictimView {
        description = "Detects SumUp phishing kit victim control view page"
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
rule SumUp_PhishKit_OTP_Page {
        description = "Detects SumUp phishing kit SMS/Email OTP harvesting pages"
        $title_sms = "Authentication - SMS" ascii
        $title_email = "Authentication - EMAIL" ascii
        $otp_input = "otp_code_input_" ascii
        $sumup_brand = "SumUp" ascii
        $move_focus = "moveFocus" ascii
        $one_time_code = "one-time-code" ascii
        $panel_processor = "../panel/classes/processor.php" ascii
rule Riptide_Proxy_Server {
        description = "Detects Riptide proxy server binary based on embedded Go package paths and function names"
        investigation = "Operation Riptide"
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
        (3 of ($pkg*)) or (2 of ($pkg*) and 2 of ($func*)) or ($dev_path and 2 of ($pkg*))
rule Riptide_Proxy_Server_Kompiuteris_Build {
        description = "Detects Riptide proxy binary compiled by 'Kompiuteris' developer"
        $dev = "C:/Users/Kompiuteris/" ascii wide
        $tg = "Telegram Desktop/riptide-main/" ascii wide
        $riptide = "riptide/internal/" ascii
        ($dev or $tg) and $riptide
rule Subway_Kount_Session_Generator {
        description = "Detects Subway Kount Session Generator credential stuffing tool"
        $name = "Subway Kount Session Generator" ascii wide
        $client_id = "efeb9bea-106d-4a27-acb4-c171474d4dda" ascii wide
        $tenant = "02d64b66-5494-461d-8e0d-5c72dc1efa7f" ascii wide
        $redirect = "subway-mobile-app://auth/" ascii wide
        $adobe_org = "D793BF115757EDD37F000101@AdobeOrg" ascii wide
        $msal = "MSAL.iOS" ascii wide
        $b2c = "b2c_1a_signin_mobile" ascii wide
        $name or ($client_id and $tenant) or (3 of them)
rule Sideload_MscorSvc_AES_Injector {
        description = "Detects malicious mscorsvc.dll used in DLL sideloading with AES decryption and process injection. Delivered via royalconstructionin[.]com as part of fake Adobe update package."
        hash = "0fbbe932a3da2cfe5b28032c3dfc5d6bc47e252b6c01264ad65a23d5b73d636e"
        reference = "https://intel.breakglass.tech/post/teomslive-com"
        $bcrypt1 = "BCryptOpenAlgorithmProvider" ascii
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii
        $bcrypt3 = "BCryptDecrypt" ascii
        $bcrypt4 = "BCryptDestroyKey" ascii
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "OpenProcess" ascii
        $enum1 = "Process32First" ascii
        $enum2 = "Process32Next" ascii
        $enum3 = "CreateToolhelp32Snapshot" ascii
        $antidbg1 = "IsDebuggerPresent" ascii
        $antidbg2 = "CheckRemoteDebuggerPresent" ascii
        $sandbox1 = "GlobalMemoryStatusEx" ascii
        pe.characteristics & pe.DLL and
        3 of ($bcrypt*) and
        2 of ($inject*) and
        2 of ($enum*) and
        1 of ($antidbg*) and
        $sandbox1
rule Sideload_MscorSvc_Encrypted_Rdata {
        description = "Detects DLLs with large high-entropy .rdata sections typical of encrypted payloads in sideloading attacks. Generic variant."
        filesize > 5MB and
        for any s in pe.sections : (
            s.name == ".rdata" and
            s.raw_data_size > 5000000 and
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7.9
rule ExcelDNA_XLL_Dropper_Invoice {
        description = "Detects Excel-DNA XLL add-in files used as malware droppers with packed assemblies. Associated with invoice-themed phishing campaigns."
        hash = "866566afef12ceded10520877c2b52c1bb17bf9a90ca4ecf4901de090042ff01"
        $dna1 = "Excel-DNA" ascii wide
        $dna2 = "ExcelDna" ascii wide
        $dna3 = "ExternalLibrary" ascii wide
        $pack1 = "packed:DEC64" ascii wide
        $pack2 = "Pack=\"true\"" ascii wide
        $net1 = ".NETFramework" ascii wide
        $net2 = "v4.6.2" ascii wide
        filesize > 200KB and filesize < 5MB and
        2 of ($dna*) and
        1 of ($pack*) and
        1 of ($net*)
rule Mscorsvw_Sideload_Carrier {
        description = "Detects legitimate Microsoft .NET Runtime Optimization Service (mscorsvw.exe) being deployed outside its normal path. When found in user directories, temp folders, or Downloads, indicates DLL sideloading attempt."
        hash = "3e824f0d325fd32f8100ddf6b506ad6250be48286ac20726dcb23a9cedf3e4c1"
        $ver1 = "mscorsvw.exe" ascii wide
        $ver2 = ".NET Runtime Optimization Service" ascii wide
        $ver3 = "Microsoft Corporation" ascii wide
        $ver4 = "2.0.50727" ascii wide
        $imp1 = "mscoree.dll" ascii
        $imp2 = "GetRealProcAddress" ascii
        $imp3 = "GetRequestedRuntimeInfo" ascii
        not pe.characteristics & pe.DLL and
        2 of ($ver*) and
        $imp1 and
        1 of ($imp2, $imp3)
rule VENON_Banker_Rust_DLL {
        description = "Detects VENON banking trojan - Rust-based Brazilian banker distributed as trojanized libcef.dll"
        hash1 = "dc7c8f5cb67148876617f387df095dcea8598726fe5599cc1d3bab18932d372d"
        hash2 = "530e501f3e0aa8a5e3a41a06b0ba4e159ea6cea258b71c644c0578b856aebddb"
        hash3 = "00dbe21b176bef396455459d7e8da3365397a47c9c54b4422a30f8dae7cb578b"
        
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
        uint16(0) == 0x5A4D and filesize < 15MB and (
            2 of ($venon*) or
            3 of ($module*) or
            (2 of ($debug*) and 1 of ($persist*)) or
            ($cargo and 1 of ($bank*)) or
            (1 of ($venon*) and 1 of ($module*) and 1 of ($bank*))
rule VENON_Banker_Behavioral {
        description = "Detects VENON banker behavioral patterns - PIX/boleto/crypto swap"
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
        uint16(0) == 0x5A4D and (
            2 of ($pix*) or
            (1 of ($boleto*) and 1 of ($crypto*)) or
            3 of ($stealth*) or
            (1 of ($ws*) and (1 of ($pix*) or 1 of ($crypto*)))
rule VENON_Banker_CEF_Sideload {
        description = "Detects trojanized libcef.dll used by VENON banker for DLL sideloading"
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
        3 of ($export*) and
        2 of ($mal*)
rule NetSupport_JAR_Dropper_UzbekLure {
        description = "Detects the MoliyaviyTahlilUZ.jar NetSupport RAT dropper targeting Uzbekistan"
        hash = "0133a8a0bc4521eb39f24563c0866fe93eb0501507a920abbae5692f60c89220"
        malware_family = "NetSupport RAT"
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
        $jar_magic at 0 and filesize < 100KB and (
            ($c2_url) or
            ($main_class and 3 of ($m*)) or
            (2 of ($v*) and 3 of ($ns*)) or
            (1 of ($ua*) and 2 of ($persist*)) or
            (2 of ($lure*) and 2 of ($ns*))
rule NetSupport_JAR_Dropper_Generic_UzbekTheme {
        description = "Generic detection for Uzbek-themed JAR droppers deploying NetSupport RAT"
        $jar = { 50 4B 03 04 }
        $uz1 = "Moliyaviy" ascii nocase
        $uz2 = "Buxgalteriya" ascii nocase
        $uz3 = "Inspeksiya" ascii nocase
        $uz4 = "soliq" ascii nocase
        $uz5 = "tahlil" ascii nocase
        $ns2 = "HTCTL32.DLL" ascii
        $java1 = "java/net/HttpURLConnection" ascii
        $java2 = "java/nio/file/Files" ascii
        $jar at 0 and filesize < 200KB and
        2 of ($uz*) and 2 of ($ns*) and all of ($java*)
rule NetSupport_RAT_Download_BatLoader {
        description = "Detects batch file loader pattern used by this NetSupport RAT campaign"
        $bat1 = "@echo off" ascii nocase
        $bat3 = /start\s+""\s+\/B\s+"/ ascii
        $bat4 = "client32.exe" ascii nocase
        $name1 = "moliyaviy_tahlil" ascii nocase
        filesize < 1KB and $bat1 and $bat3 and ($bat4 or $name1)
rule LofyGang_NYX_Stealer_npm_Package {
        description = "Detects LofyGang NYX Stealer npm package (XOR-encrypted payload)"
        hash = "bad0fd9a966e4eb7edfaa7e19da025f9be3c1541de22b5ca76afb9afbc0b548f"
        $xor_key = "qA#s5~d/YLcg5c;^r7$x" ascii
        $wrapper1 = "const _k=" ascii
        $wrapper2 = "_d=Buffer.from(" ascii
        $wrapper3 = "new Function(\"require\"" ascii
        $wrapper4 = "_r[_i]=_d[_i]^_k.charCodeAt" ascii
        $xor_key or (2 of ($wrapper*))
rule LofyGang_NYX_Stealer_Decrypted_Payload {
        description = "Detects decrypted LofyGang NYX Stealer JavaScript payload"
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
rule LofyGang_ChromeElevator_Stealer {
        description = "Detects LofyGang chromelevator.exe native stealer"
        hash = "d6090c843c58f183fb5ed3ab3f67c9d96186d1b30dfd9927b438ff6ffedee196"
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
        uint16(0) == 0x5A4D and filesize < 5MB and 4 of ($s*)
rule LofyGang_npm_Maintainer_Pattern {
        description = "Detects npm packages by known LofyGang maintainer account"
        $email = "duba70015@gmail.com" ascii
        $maintainer = "consolelofy" ascii
        $pkg1 = "separadordeinfocc" ascii
        $pkg2 = "undicy-http" ascii
rule LofyGang_Discord_Webhook_Exfil {
        description = "Detects LofyGang specific Discord webhook and Telegram exfiltration"
        $webhook = "1484725829412851915" ascii
        $tg_bot = "8713069597:AAHVJGtP17y2cYnPAk8j0ro0fhuJuNP9Uak" ascii
        $tg_chat = "8245283894" ascii
        $steam_key = "440D7F4D810EF9298D25EDDF37C1F902" ascii
rule Trojanized_ZKM_ResourceMonitor {
        description = "Detects trojanized Zelix KlassMaster obfuscator with ResourceMonitor RAT payload using DoH-based C2"
        hash = "cb574adcec44a9b051269d23bd4567b876253c068c3b30835ff38aec85d49d55"
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
        uint16(0) == 0x504B and  // ZIP/JAR magic
        filesize > 5MB and filesize < 20MB and
        ($manifest_zkm and $class_rm) or
        ($source_patch and any of ($drop_*)) or
        ($doh_url and $doh_ct and $c2_domain) or
        3 of ($drop_qt, $drop_jar, $task_name, $crack_leaks, $xor_key)
rule MCLeaks_DoH_RAT_Generic {
        description = "Detects Java RAT using DNS-over-HTTPS to cloudflare-dns.com for C2 resolution"
        $doh1 = "cloudflare-dns.com" ascii wide
        $doh2 = "dns-query" ascii wide
        $doh3 = "application/dns-message" ascii wide
        $java1 = "URLClassLoader" ascii
        $java2 = "loadClass" ascii
        $java3 = "getManifest" ascii
        $java4 = "Main-Class" ascii
        $java5 = "ProcessBuilder" ascii
        $mcleaks = "mcleaks" ascii wide nocase
        (uint16(0) == 0x504B or uint32(0) == 0xCAFEBABE) and
        2 of ($doh*) and
        2 of ($java*) and
        $mcleaks
rule ResourceMonitor_PatchSystem_Dropper {
        description = "Detects ResourceMonitor/PatchSystem Java dropper class"
        $source = "PatchSystem.java" ascii
        $class = "ResourceMonitor" ascii
        $method1 = "schtasks" ascii wide
        $method2 = "javaw.exe" ascii wide
        $method3 = "CREATE_NEW" ascii
        $method4 = "SecretKeySpec" ascii
        $method5 = "URLClassLoader" ascii
        $drop1 = "874643384254" ascii wide
        $drop2 = "qtshadercache" ascii wide
        uint32(0) == 0xCAFEBABE and  // Java class magic
        $source and
        ($class or 2 of ($method*) or any of ($drop*))
rule Stealc_Gate_PHP_Path {
        description = "Detects Stealc stealer C2 gate PHP path pattern observed on Intezio BPH infrastructure"
        reference = "ThreatFox IOC 150.241.65.94/sc32"
         = /\/[a-f0-9]{16}\.php/ ascii wide
         = "Mozilla/5.0 (Windows NT" ascii
         = "hwid" ascii nocase
         = "build_id" ascii nocase
         = "token" ascii nocase
         and 2 of (*)
rule Intezio_BPH_Network_Strings {
        description = "Detects references to Intezio bulletproof hosting network in malware configs or scripts"
         = "150.241.65." ascii wide
         = "103.101.85." ascii wide
         = "138.124.100." ascii wide
         = "138.124.104." ascii wide
         = "138.124.105." ascii wide
         = "138.124.106." ascii wide
         = "77.239.114." ascii wide
         = "154.43.57." ascii wide
         = "194.238.57." ascii wide
         = "168.222.254." ascii wide
         = "81.90.25." ascii wide
         = "inteid.net" ascii wide nocase
         = "dns-stat.com" ascii wide nocase
         = "intezio.net" ascii wide nocase
        2 of (*) or any of (*)
rule Shellcode_Delivery_sc32_Pattern {
        description = "Detects URL patterns consistent with shellcode delivery at /sc32 or /sc64 endpoints"
        reference = "ThreatFox IOC hxxp://150.241.65.94/sc32"
         = "/sc32" ascii wide
         = "/sc64" ascii wide
         = "150.241.65.94" ascii wide
        any of (, ) and any of (, )
rule Kortex_RAT_PKG_Binary {
        description = "Detects Kortex RAT - Node.js RAT packed with Vercel pkg, uses GitHub Gist dead-drop for C2 resolution"
        hash = "bf3af0269374ac1312e4a478480678a8f5988a206e1f150fe54cd07e77fdf5a8"
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
        filesize > 40MB and filesize < 60MB and
            (any of ($pkg_marker*)) or
            ($gist_url) or
            ($gist_id) or
            (3 of ($dep_*) and $node_ver)
rule Kortex_RAT_MSI_Dropper {
        description = "Detects Kortex RAT MSI dropper - trojanized Element 3D installer"
        hash = "455bf1be7ee17e25e99054d04f83c512b1f4c886f3ce2868831b7c04d9635392"
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $product1 = "System Service" ascii wide
        $product2 = "SystemService_8436" ascii wide
        $action = "cmd.exe /c start /b svchost.exe" ascii wide
        $upgrade = "{9054E078-8F0D-435A-9A8C-7B7261229952}" ascii wide
        $product_code = "{FE8E87C3-3A2E-4970-9371-ECEF23F3C5BC}" ascii wide
        $msi_magic at 0 and
        filesize > 10MB and filesize < 25MB and
            ($action) or
            ($product1 and $product2) or
            (any of ($upgrade, $product_code))
rule Kortex_RAT_WebSocket_C2_Config {
        description = "Detects Kortex RAT C2 configuration patterns in Node.js PKG binaries"
        $ws_c2_1 = "ws://2.27.28.167:6062" ascii
        $ws_c2_2 = "ws://144.31.84.211:6062" ascii
        $ws_c2_3 = "ws://83.217.208.72:6062" ascii
        $gist = "HexReaper" ascii
        $port = ":6062" ascii
        any of ($ws_c2_*) or
        ($gist and $port)
rule GOVTI_V4_Agent_Go_Botnet {
        date = "2026-04-02"
        description = "Detects GOVTI V4 Go botnet agent binary"
        hash_amd64 = "eb2db389d64987855fa5db905bbcb7b100f9d6c1699eaf5d846a98680feae1df"
        hash_arm64 = "c0a1e299afefd7fd9f718c4e1ce2a50eb745ce3485365ef3b671995793aa2ff7"
        $build1 = "/Volumes/2T/govti/agent_src/" ascii
        $build2 = "mod_c2.go" ascii
        $build3 = "mod_ddos.go" ascii
        $build4 = "mod_luapoc.go" ascii
        $build5 = "mod_privesc.go" ascii
        $build6 = "core_spread.go" ascii
        $build7 = "mod_intranet.go" ascii
        $build8 = "mod_dyn_c2.go" ascii
        $op1 = "=== APT Task Server Started ===" ascii
        $op2 = "# Auto-generated by GOVTI Agent" ascii
        $op3 = "# Auto-patch by GOVTI Agent" ascii
        $op4 = "govti_v4" ascii
        $op5 = "queen_summoned" ascii
        $op6 = "FUNNY_CHANNEL" ascii
        $persist1 = "/usr/local/bin/.apt-task" ascii
        $persist2 = "/tmp/.apt-task.pid" ascii
        $persist3 = "apt-task.service" ascii
        $persist4 = "APTTaskService" ascii
        $c2_1 = "/c/beacon" ascii
        $c2_2 = "/c/targets" ascii
        $c2_3 = "/c/scan_done" ascii
        $c2_4 = "/api/heartbeat" ascii
        $c2_5 = "/static/pocs.tar.gz" ascii
        $spread1 = "GOT_SHELL" ascii
        $spread2 = "sshpass -p" ascii
        $spread3 = "VULN_CONFIRMED" ascii
        $spread4 = "NOT_VULNERABLE" ascii
        $seo1 = "seo_optimize.conf" ascii
        $seo2 = "seo_rules.json" ascii
        $seo3 = "seo_whitelist.conf" ascii
        $lua1 = "gopher-lua" ascii
        $lua2 = "LuaModule" ascii
        (uint32(0) == 0x464C457F) and filesize > 5MB and filesize < 15MB and (
            any of ($build*) or
            2 of ($op*) or
            (2 of ($persist*) and 1 of ($c2*)) or
            (2 of ($c2*) and 1 of ($spread*)) or
            (1 of ($seo*) and 1 of ($c2*) and 1 of ($persist*))
rule GOVTI_V4_Dropper_Script {
        description = "Detects GOVTI V4 shell dropper scripts"
        $d1 = ".apt-task" ascii
        $d2 = "8899/dl" ascii
        $d3 = "16881/dl" ascii
        $d4 = "chmod +x .svc" ascii
        $d5 = "nohup ./.svc" ascii
        $d6 = "103.79.79.21" ascii
        $d7 = "/dl/updater" ascii
        filesize < 5KB and 2 of ($d*)
rule GOVTI_V4_SEO_Config_Injection {
        description = "Detects GOVTI V4 SEO parasiting config injections in web server files"
        $s1 = "Auto-generated by GOVTI Agent" ascii
        $s2 = "Auto-patch by GOVTI Agent" ascii
        $s3 = "SEO optimization - auto generated" ascii
        filesize < 500KB and any of them
rule GOVTI_V4_Persistence_Artifacts {
        description = "Detects GOVTI V4 persistence artifacts (systemd service, crontab)"
        $p1 = "apt-task.service" ascii
        $p2 = "APTTaskService" ascii
        $p3 = ".apt-task.pid" ascii
        $p4 = "/usr/local/bin/.apt-task" ascii
import "pe"
   NKFZ5966 Boeing RFQ Campaign -- Deep Attribution YARA Rules
   Author: GHOST - Breakglass Intelligence
   Date: 2026-04-01
   Reference: https://intel.breakglass.tech
*/
        description = "Detects JS dropper variants from NKFZ5966 campaign"
        $sep1 = "tZaVLLetjJ" ascii
        $sep2 = "IaYvjqgOMp" ascii
        $sep3 = "BSjvbAiAMv" ascii
        $wscript = "WScript.Shell" ascii
        $split_join = ".split(" ascii
        $join_empty = ".join(\"\")" ascii
        any of ($sep*) and ($wmi or $wscript) and $split_join
        description = "Detects DOCX lure documents from NKFZ5966 campaign by metadata"
        $modifier = "<dc:creator>Christian Booc</dc:creator>" ascii
        $rtf_names = /(rsuas|fetim|reato)\.rtf/ ascii
        uint32(0) == 0x04034B50 and ($creator or $modifier) and ($afchunk or $rtf_names)
        description = "Detects the PowerShell downloader from NKFZ5966 campaign"
        $callbyname = "CallByName" ascii wide
        $filemail = "filemail.com" ascii wide nocase
        $python312 = "python312x64" ascii wide
        $templates = "Templates" ascii wide
        $syncappv = "SyncAppvPublishingServer" ascii wide
        $rtkaud = "RtkAudUService" ascii wide
rule GOVTI_V4_Agent {
        description = "Detects GOVTI V4 botnet agent (Go binary)"
        hash_amd64 = "see investigation"
        hash_arm64 = "see investigation"
        $pdb1 = "/Volumes/2T/govti/agent_src/main.go" ascii
        $pdb2 = "/Volumes/2T/govti/agent_src/mod_c2.go" ascii
        $pdb3 = "/Volumes/2T/govti/agent_src/mod_ddos.go" ascii
        $pdb4 = "/Volumes/2T/govti/agent_src/mod_seo.go" ascii
        $pdb5 = "/Volumes/2T/govti/agent_src/core_spread.go" ascii
        $func1 = "main.(*DDoSModule).ExecuteDDoS" ascii
        $func2 = "main.(*SEOModule).autoSeoHijack" ascii
        $func3 = "main.(*DHTProtocol).applyConfig" ascii
        $func4 = "main.(*IntranetModule).runIntranetScan" ascii
        $func5 = "main.telnetSpreadOnce" ascii
        $func6 = "main.c2HarvestCredentials" ascii
        $func7 = "main.reportToGoatCounter" ascii
        $func8 = "main.selfDestructC2" ascii
        $str1 = "ASC2_v3_PreSharedKey_ChangeMe!" ascii
        $str2 = "queen_summoned" ascii
        $str3 = "APTTaskService" ascii
        $str4 = "FUNNY_CHANNEL" ascii
        $str5 = "govti_v4" ascii
        $str6 = "hdt_config.txt" ascii
        $str7 = "seo_rules.json" ascii
        $str8 = "/usr/local/bin/.apt-task" ascii
        $c2_1 = "/api/heartbeat" ascii
        $c2_2 = "/c/beacon" ascii
        $c2_3 = "/dl/updater" ascii
        $c2_4 = "http://%s:8899" ascii
        $c2_5 = "http://%s:16881/dl" ascii
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and
        (2 of ($pdb*) or 3 of ($func*) or 4 of ($str*) or 3 of ($c2*))
        description = "Detects GOVTI V4 dropper/updater shell script"
        $s1 = "/tmp/.svc" ascii
        $s2 = "linux_amd64" ascii
        $s3 = "linux_arm64" ascii
        $s4 = "nohup ./.svc" ascii
        $s5 = ":8899/dl/" ascii
        $s6 = ":16881/dl" ascii
        $s7 = "chmod +x .svc" ascii
        filesize < 2KB and 3 of them
rule GOVTI_V4_SEO_Config {
        description = "Detects GOVTI V4 SEO injection configuration files"
        $s1 = "seo_whitelist" ascii
        $s2 = "Googlebot" ascii
        $s3 = "YandexBot" ascii
        $s4 = "360Spider" ascii
        $s5 = "Auto-generated by GOVTI Agent" ascii
        $s6 = "Auto-patch by GOVTI Agent" ascii
        $s7 = "seo_whitelisted" ascii
rule GOVTI_V4_Persistence_Indicator {
        description = "Detects GOVTI V4 systemd persistence artifacts"
        $s1 = "APTTaskService" ascii
        $s2 = "apt-task" ascii
        $s3 = "/usr/local/bin/.apt-task" ascii
        $s4 = "SyslogIdentifier=apt-task" ascii
rule APT41_Winnti_ELF_Backdoor_2026 {
        date = "2026-04-03"
        description = "Detects APT41/Winnti ELF backdoor with cloud metadata harvesting and obfuscated payload"
        hash = "0fca9dae54a7a55f0805a864e9d2911d727a6e274f4ddc9b5673078130e0f9e1"
        threat_actor = "APT41/Winnti"
        // Network imports indicating raw socket C2
        $imp_socket = "socket" ascii
        $imp_connect = "connect" ascii
        $imp_sendto = "sendto" ascii
        $imp_recvfrom = "recvfrom" ascii
        $imp_setsockopt = "setsockopt" ascii
        $imp_getsockopt = "getsockopt" ascii
        $imp_inet_pton = "inet_pton" ascii
        // Anti-debug
        $imp_ptrace = "ptrace" ascii
        // Daemonization
        $imp_daemon = "daemon" ascii
        $imp_fork = "fork" ascii
        // Dynamic loading (plugin capability)
        $lib_dl = "libdl.so.2" ascii
        // XOR hint
        $xor_hint = "ioXor" ascii
        // Threading
        $imp_pthread_create = "pthread_create" ascii
        $imp_pthread_detach = "pthread_detach" ascii
        // Process execution
        $imp_execve = "execve" ascii
        $imp_system = "system" ascii
        // Memory manipulation
        $imp_mprotect = "mprotect" ascii
        // File system enumeration
        $imp_scandir = "scandir64" ascii
        $imp_readdir = "readdir64" ascii
        uint32(0) == 0x464C457F and  // ELF magic
        filesize > 2MB and filesize < 5MB and
        $lib_dl and
        $imp_ptrace and
        $imp_daemon and
        $imp_mprotect and
        6 of ($imp_socket, $imp_connect, $imp_sendto, $imp_recvfrom, $imp_setsockopt, $imp_getsockopt, $imp_inet_pton) and
        2 of ($imp_pthread_create, $imp_pthread_detach) and
        ($imp_execve or $imp_system)
rule APT41_Winnti_ELF_Backdoor_C2_Domains {
        description = "Detects APT41/Winnti C2 domain indicators in any file type"
        $c2_1 = "qianxing.co" ascii wide nocase
        $c2_2 = "a1iyun.top" ascii wide nocase
        $c2_3 = "aliyuncs.help" ascii wide nocase
        $c2_ip = "43.99.48.196" ascii wide
rule APT41_Winnti_ELF_Obfuscated_Payload {
        description = "Detects ELF binaries with large obfuscated code sections typical of Winnti family"
        $elf_magic = { 7F 45 4C 46 }
        $imp_dlopen = "libdl.so" ascii
        $imp_pthread = "pthread_create" ascii
        $elf_magic at 0 and
        filesize > 1MB and
        all of ($imp_*) and
        // High entropy check - large section of near-random data (obfuscated code)
        math.entropy(0xa0000, 0xd0000) > 7.9
rule BGI_C2_Cookie_Theft_Panel {
        description = "Detects the cookie theft C2 dashboard HTML"
        $title = "Attacker C2 - Stolen Cookies" ascii wide
        $wait = "Waiting for Stored XSS to fire" ascii wide
        $total = "Total stolen sessions" ascii wide
        $css1 = "background: #1a1a2e" ascii
        $css2 = "color: #e94560" ascii
rule BGI_Tracking_Pixel_Cookie_Exfil {
        description = "Detects 1x1 GIF89a tracking pixel used for cookie exfiltration"
        $gif = { 47 49 46 38 39 61 01 00 01 00 80 00 00 FF FF FF 00 00 00 21 F9 04 00 00 00 00 00 2C 00 00 00 00 01 00 01 00 00 02 02 44 01 00 3B }
        $gif at 0 and filesize < 100
rule BGI_Electrum_Phishing_Kit {
        description = "Detects cloned Electrum Bitcoin Wallet download page"
        $title = "<title>Electrum Bitcoin Wallet</title>" ascii
        $dl1 = "download.electrum.org/4.7.1" ascii
        $css = "electrum.css" ascii
        $sprites = "sprites.css" ascii
        $signer = "ThomasV" ascii
        $signer2 = "SomberNight" ascii
        $title and 2 of ($dl1, $css, $sprites, $signer, $signer2)
rule ClickFix_Deno_Implant_Generic {
        description = "Detects Deno-based ClickFix MaaS implant JS payload"
        hash = "8ceb89e7e4c4cfe20ea5df2f0762967fa8f3f502f2696abbe2baa0c6b437841b"
        // Deno API calls used by the implant
        $deno1 = "Deno.listen" ascii
        $deno2 = "Deno.env" ascii
        $deno3 = "Deno.hostname" ascii
        $deno4 = "Deno.systemMemoryInfo" ascii
        $deno5 = "Deno.osRelease" ascii
        $deno6 = "Deno.Command" ascii
        $deno7 = "Deno.writeTextFile" ascii
        $deno8 = "Deno.execPath" ascii
        // C2 protocol markers
        $c2_1 = "x-module-request" ascii
        $c2_2 = "x-huid" ascii
        $c2_3 = "x-username" ascii
        $c2_4 = "x-hostname" ascii
        $c2_5 = "/health" ascii
        $c2_6 = "/session" ascii
        // JWT structure
        $jwt = "eyJhbGciOiJIUzI1NiI" ascii
        // Persistence indicators
        $persist1 = "CurrentVersion\\Run" ascii wide
        $persist2 = "conhost" ascii
        $persist3 = "--headless" ascii
        $persist4 = "-WindowStyle" ascii
        $persist5 = "Hidden" ascii
        filesize < 100KB and
            (3 of ($deno*) and 2 of ($c2*)) or
            ($jwt and 2 of ($deno*)) or
            (4 of ($deno*) and any of ($persist*))
rule ClickFix_Deno_Smokest_Build {
        description = "Detects specific ClickFix build by operator Smokest"
        $build_id = "3c736f7304ddeadb" ascii
        $user_id = "1943c7b8c0a029e2" ascii
        $token_hash = "2e9812a0dc5998a3f9a59fe6" ascii
        $build_note = "BatClickFixPS1NewV1" ascii
        filesize < 100KB and any of them
rule ClickFix_Deno_Obfuscation_Pattern {
        description = "Detects the obfuscation pattern used by the ClickFix Deno MaaS builder"
        // String table rotation pattern
        $obf1 = "const Store=channel" ascii
        $obf2 = "const Plugin=Stream()" ascii
        $obf3 = "channel['yCzHrH']" ascii
        $obf4 = "channel['zzSmtT']" ascii
        $obf5 = "channel['vmPCAw']" ascii
        // Fiber/Settings array pattern
        $arr1 = "function fiber(){" ascii
        $arr2 = "const Settings=[" ascii
        // AddrInUse mutex check
        $mutex = "AddrInUse" ascii
            (2 of ($obf*)) or
            ($arr1 and $arr2) or
            ($mutex and any of ($obf*))
rule FEZBOX_QR_Payload {
        description = "Detects FEZBOX supply chain attack QR code JavaScript payload"
        hash = "a4cd83a3e43ac218257089d08afcdd7dfc95c73979f459fbfeec9a55da62d304"
        $s1 = "[FEZBOX]" ascii wide
        $s2 = "Malicious payload activated" ascii wide
        $s3 = "/collect" ascii wide
        $s4 = "document.cookie" ascii wide
        $s5 = "1.94.210.59" ascii wide
        $s6 = "8080" ascii wide
        ($s1 and $s2) or ($s1 and $s3) or ($s5 and $s6 and $s3)
rule FEZBOX_NPM_Exfil {
        description = "Detects FEZBOX npm supply chain attack exfiltration payload"
        $type = "nodejs_supply_chain_attack" ascii wide
        $phase = "exfiltration" ascii wide
        $test = "fezbox-supply-chain-test" ascii wide
        $pkg = "fezbox" ascii wide
        $c2_1 = "1.94.210.59" ascii wide
        $c2_2 = "/collect" ascii wide
        $marker = "maliciousPackage" ascii wide
        ($type and $phase) or ($test) or ($pkg and ($c2_1 or $c2_2)) or ($marker and $c2_1)
rule FEZBOX_C2_Panel {
        description = "Detects FEZBOX C2 panel HTML content"
        $title = "DARKNET C2 CONTROL PANEL" ascii wide
        $system = "darknet_c2_hacker" ascii wide
        $log = "/opt/malicious/exfiltrated_data.log" ascii wide
        $health = "darknet_c2_hacker" ascii wide
        $panel = "C2 Monitor Panel" ascii wide
rule MSC_GrimResource_Technique {
        description = "Detects MSC files using GrimResource apds.dll XSS technique"
        $apds1 = "res://apds.dll" ascii wide nocase
        $apds2 = "redirect.html" ascii wide nocase
        $eval1 = "javascript:eval" ascii wide nocase
        $scope1 = "ScopeNamespace" ascii wide
        $scope2 = "GetRoot" ascii wide
        $mmc_header = "MMC_ConsoleFile" ascii
        $hex_apds = { 26 23 78 36 31 3b 26 23 78 37 30 3b 26 23 78 36 34 3b 26 23 78 37 33 3b }
        $mmc_header and (($apds1 and $apds2) or ($eval1 and $scope1) or $hex_apds)
rule MSC_ExecuteShellCommand {
        description = "Detects MSC files using ExecuteShellCommand for code execution"
        $exec1 = "ExecuteShellCommand" ascii wide
        $exec2 = "external.ExecuteShellCommand" ascii wide
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "cmd.exe" ascii wide nocase
        ($mmc_header and $exec1) or ($exec2 and any of ($ps*))
rule MSC_XSLT_Code_Execution {
        description = "Detects MSC files using XSLT transforms with embedded script"
        $xslt1 = "transformNode" ascii wide
        $xslt2 = "ms:script" ascii wide
        $mmc = "MMC_ConsoleFile" ascii
        $active1 = "ActiveXObject" ascii wide
        $mmc and ($xslt1 or $xslt2) and $active1
rule Mythic_Coffee_Agent {
        description = "Detects Mythic C2 coffee agent (Rust-based)"
        $s1 = "coffeeuploadc2_updatedownloadcontinued_tasksleepexit" ascii
        $s2 = "struct Aespsk with 3 elements" ascii
        $s3 = "struct AgentMessage" ascii
        $s4 = "struct DynamicHttpTestAgentConfig" ascii
        $s5 = "pc2g" ascii
        $s6 = "enc_keydec_key" ascii
        $s7 = "ServerETagCache-ControlKeep-Alive" ascii
        $psk = "H0QmHqnUMbcVE6M3vAHZ52ZQ5dFbsFfkDJlcugxKcZ0=" ascii
        uint16(0) == 0x5A4D and (3 of ($s*) or $psk)
rule LOTUSLITE_Backdoor {
        description = "Detects LOTUSLITE backdoor attributed to Mustang Panda"
        $mutex = "Technology360-A@P@T-Team" ascii wide
        $persist = "Lite360" ascii wide
        $path = "Technology360NB" ascii wide
        $magic = { 88 99 AA BB }
        $ua = "Googlebot" ascii
        $export1 = "DataImporterMain" ascii
        $export2 = "EvtNext" ascii
        $export3 = "EvtQuery" ascii
        uint16(0) == 0x5A4D and (2 of ($mutex, $persist, $path) or ($magic and $ua) or all of ($export*))
rule MSC_Malicious_StringTable {
        description = "Detects MSC files with suspicious C2 URLs in StringTable"
        $st = "StringTable" ascii
        $workers = ".workers.dev" ascii wide nocase
        $pages = ".pages.dev" ascii wide nocase
        $s3_fake = "amazonaws-com" ascii wide nocase
        $ps_cmd = "powershell" ascii wide nocase
        $mmc and $st and (any of ($workers, $pages, $s3_fake) or $ps_cmd)
rule DLL_Sideload_MSDTC_Xolehlp {
        description = "Detects malicious xolehlp.dll for msdtc.exe DLL sideloading"
        $export1 = "DtcGetTransactionManager" ascii
        $export2 = "FreezeLocalTransactionManagers" ascii
        $export3 = "ThawLocalTransactionManagers" ascii
        $winhttp = "winhttp.dll" ascii
        $mythic1 = "AgentMessage" ascii
        $mythic2 = "aes256_hmac" ascii
        uint16(0) == 0x5A4D and all of ($export*) and ($winhttp or any of ($mythic*))
rule MefStealer_C2_Panel_HTML {
        description = "Detects MefStealer C2 panel HTML landing page"
        $title = "<title>MefStealer</title>" ascii
        $brand = "NOMADS" ascii
        $hero = "MefStealer" ascii
        $panel_link = "/webpanel" ascii
        $subtitle = "Revolutionary stealer" ascii
        $c2_title = "MefStealer C2" ascii
        $stat_tdata = "TData" ascii
        $stat_cookies = "Cookies" ascii
        $stat_wallets = "Wallets" ascii
        $title or ($brand and $panel_link) or ($c2_title and 2 of ($stat_*))
rule MefStealer_C2_Panel_JS {
        description = "Detects MefStealer C2 panel JavaScript"
        $api_users = "fetch(\"/users\")" ascii
        $api_user_info = "/user/" ascii
        $api_download = "/download/" ascii
        $func_load = "loadUsers" ascii
        $func_delete = "deleteUser" ascii
        $func_panel = "loadUserPanel" ascii
        $func_files = "loadFiles" ascii
        $func_preview = "loadFilePreview" ascii
        $comment_ru1 = {D0 97 D0 B0 D0 B3 D1 80 D1 83 D0 B7 D0 BA D0 B0}
        $comment_ru2 = {D0 A3 D0 B4 D0 B0 D0 BB D0 B5 D0 BD D0 B8 D0 B5}
        4 of ($func_*) or ($api_users and $api_download and 2 of ($func_*)) or any of ($comment_ru*)
rule MefStealer_Gate_Response {
        description = "Detects MefStealer gate/receiver HTTP responses"
        $health = "cache_size" ascii
        $pending = "pending_writes" ascii
        $status = "\"status\":\"running\"" ascii
        $uptime = "\"uptime\":\"ok\"" ascii
        $no_file = "\"error\":\"No file part\"" ascii
        $werkzeug = "Werkzeug" ascii
        ($health and $pending) or ($status and $uptime) or ($no_file and $werkzeug)
rule PlugX_Mongolia_CNCLID_Loader {
        description = "PlugX loader DLL (CNCLID.dll) in TA416 campaign targeting Mongolia"
        hash = "5884563b28cd4b470066780003b1c8e2a6025d453ae3e80dcea6891a3944db60"
        $export = "GetLangID" ascii
        $import1 = "BCryptGenRandom" ascii
        $s1 = "Canon.dat" wide ascii
        uint16(0) == 0x5A4D and filesize < 200KB and $export and $import1 and $s1
rule PlugX_Mongolia_RigsterHook_Loader {
        description = "PlugX loader with misspelled RigsterHook export - Mustang Panda artifact"
        uint16(0) == 0x5A4D and filesize < 2MB and ($export1 or $export2)
rule PlugX_Paranoid_XOR_C6_Payload {
        description = "PlugX Paranoid encrypted payload with XOR 0xC6 shellcode stub"
        hash = "58101378fc8b3b7f989f7a4336a5c5de49effdd38f854d96dcee7ebedec09b57"
        $xor_stub = { 85 d2 e8 00 [2] 00 8B 9C }
        filesize > 100KB and filesize < 1MB and $xor_stub at 0
rule PlugX_Paranoid_Decrypted_Canon {
        description = "Decrypted PlugX Paranoid with Canon sideload references"
        hash = "ee90fb2e98d81e5e8c11aee1242398bb42ee7af8f5017905c84f491bc11650a1"
        $s1 = "Canon.dat" wide
        $s2 = "CNMNSST.exe" wide
        $s3 = "CNCLID.dll" wide
        $s4 = "SS.LOG" wide
        $s5 = "tmp.dat" wide
        $s6 = "iediagcmd.exe" wide
        $timing = { 88 13 00 00 60 EA 00 00 }
        uint16(0) == 0x5A4D and filesize < 500KB and 3 of ($s*) and $timing
rule PlugX_Mongolia_LNK_Dropper {
        description = "Malicious LNK with PowerShell ZIP search and TAR extraction"
        hash = "ddcf3af805f277e33c0a50c757789b4bc835b97e4a065e54d97e6dd4a7b280c1"
        $zip = ".zip" ascii wide
        $tar = "TaR" ascii wide nocase
        $sleep = "Sleep -Seconds" ascii wide
        $localapp = "LocalAppdata" ascii wide nocase
        filesize < 10KB and $ps1 and $zip and $tar and $sleep and $localapp
rule PlugX_Imphash_TA416_Mar2026 {
        description = "PlugX loader DLLs by imphash - TA416 March 2026 cluster"
            pe.imphash() == "72e71b666d5c764a80f4f705ed843ea4" or
            pe.imphash() == "551af7f202e2768c63b16f27eadd2d27" or
            pe.imphash() == "ad418910d838a6276d9c898b9c97ea86"
    SideWinder APT - Azerbaijan-Russia Diplomatic Crisis Campaign
    Author: GHOST - Breakglass Intelligence
    Date: 2026-04-03
    TLP: WHITE
import "hash"
rule Sidewinder_DOCX_RemoteTemplate_Azerbaijan {
        description = "SideWinder APT DOCX with remote template injection targeting Azerbaijan-Russia diplomatic crisis"
        hash1 = "f69708c769f3d34fc0798257b472cc48770208b6862ea3e6540d12b9f23f9cdf"
        hash2 = "7b5d44a88f1dfbf8c8b1a933cde2c04e4e20d4a3b9375a65c4a23cd077a0e587"
        $zip_header = { 50 4B 03 04 }
        $rel1 = "defence-np.net" ascii wide
        $rel2 = "azerbaijan" ascii wide nocase
        $rel3 = "diplomat" ascii wide nocase
        $rel4 = "Font_Updates.rtf" ascii wide
        $rel5 = "files-fd3708f2" ascii wide
        $office_rel = "schemas.openxmlformats.org/officeDocument" ascii
        $template_rel = "Target=\"http" ascii
        $zip_header at 0 and filesize < 100KB and $office_rel and (
            ($rel1) or
            ($rel2 and $rel3) or
            (2 of ($rel4, $rel5)) or
            ($template_rel and $rel1)
rule Sidewinder_DOCX_RemoteTemplate_Generic {
        description = "Generic SideWinder DOCX with remote template injection - matches known C2 domain patterns"
        $template_mode = "TargetMode=\"External\"" ascii
        // Known SideWinder C2 domains (2024-2026)
        $sw_c2_1 = "defence-np.net" ascii wide
        $sw_c2_2 = "army-govbd.info" ascii wide
        $sw_c2_3 = "modpak.info" ascii wide
        $sw_c2_4 = "pmd-office.info" ascii wide
        $sw_c2_5 = "dirctt888.info" ascii wide
        $sw_c2_6 = "dowmloade.org" ascii wide
        $sw_c2_7 = "dowmload.co" ascii wide
        $sw_c2_8 = "d0wnlaod.com" ascii wide
        $sw_c2_9 = "document-viewer.info" ascii wide
        $sw_c2_10 = "ms-office.app" ascii wide
        $sw_c2_11 = "ms-office.pro" ascii wide
        $sw_c2_12 = "updates-installer.store" ascii wide
        // Known SideWinder RTF payload names
        $rtf_name1 = "Accept_EULA.rtf" ascii wide
        $rtf_name2 = "Font_Updates.rtf" ascii wide
        $rtf_name3 = "MSFT_CLD_Font.rtf" ascii wide
        $rtf_name4 = "Microsoft_License.rtf" ascii wide
        $rtf_name5 = "Documentation_EULA.rtf" ascii wide
        $rtf_name6 = "Fontlayer.rtf" ascii wide
        $rtf_name7 = "Office.rtf" ascii wide
        $zip_header at 0 and filesize < 200KB and $office_rel and $template_mode and (
            any of ($sw_c2_*) or
            2 of ($rtf_name*)
rule Sidewinder_Decoy_RTF_Campaign_Linker {
        description = "SideWinder shared 8-byte decoy RTF dropped post-exploitation across 60+ campaigns"
        hash = "1955c6914097477d5141f720c9e8fa44b4fe189e854da298d85090cbc338b35a"
        filesize == 8 and
        hash.sha256(0, filesize) == "1955c6914097477d5141f720c9e8fa44b4fe189e854da298d85090cbc338b35a"
rule Sidewinder_C2_URL_Pattern_Memory {
        description = "SideWinder C2 numeric URL path pattern in process memory or files"
        // SideWinder C2 URL path structure: /NNNN/N/NNNNN/N/NN/N/N/m/
        $url_pattern = /https?:\/\/[a-z0-9\-]{10,80}\.[a-z\-]{5,30}\.(net|com|org|info|live|pro|email)\/\d{3,5}\/\d\/\d{4,6}\/\d\/\d{1,3}\/\d\/\d\/[a-z]\// ascii wide
        // Specific defence-np.net indicators
        $defence_np = "defence-np.net" ascii wide
        $az_crisis = "azerbaijan-russia" ascii wide
rule Sidewinder_StealerBot_DLL_Sideload_Targets {
        description = "Detects potential SideWinder Backdoor Loader DLLs based on known sideload target names with suspicious characteristics"
        // DLL names known to be sideloaded by SideWinder
        $dll1 = "propsys.dll" ascii wide fullword
        $dll2 = "vsstrace.dll" ascii wide fullword
        $dll3 = "JetCfg.dll" ascii wide fullword
        $dll4 = "policymanager.dll" ascii wide fullword
        $dll5 = "winmm.dll" ascii wide fullword
        $dll6 = "xmllite.dll" ascii wide fullword
        $dll7 = "dcntel.dll" ascii wide fullword
        $dll8 = "UxTheme.dll" ascii wide fullword
        $dll9 = "devobj.dll" ascii wide fullword
        $dll10 = "wdscore.dll" ascii wide fullword
        // StealerBot module indicators
        $mod1 = { CA 00 00 00 }  // Keylogger module ID
        $mod2 = { CB 00 00 00 }  // Live Console module ID
        $mod3 = { D0 00 00 00 }  // Screenshot module ID
        $mod4 = { D4 00 00 00 }  // File Stealer module ID
        $mod5 = { D6 00 00 00 }  // UACBypass module ID
        $mod6 = { E0 00 00 00 }  // RDP Cred Stealer module ID
        $mod7 = { E1 00 00 00 }  // Token Grabber module ID
        // .NET indicators for StealerBot
        $net1 = "ModuleInstaller" ascii wide
        $net2 = "StealerBot" ascii wide
        $net3 = "Interop.TaskScheduler" ascii wide
        $net4 = "SyncBotService" ascii wide
        uint16(0) == 0x5A4D and filesize < 10MB and (
            (any of ($dll*) and 2 of ($mod*)) or
            2 of ($net*)
rule NuttenTunnel_LNK_WebDAV_Loader {
        description = "Detects LNK files targeting trycloudflare.com WebDAV for malware delivery"
        hash = "7082ed18f1eaaccfdea66bfa51aa6d00113dadf35b9d60d5688604b9744c1c01"
        $lnk_header = { 4C 00 00 00 01 14 02 00 }
        $webdav_tunnel = "trycloudflare.com@SSL" ascii wide nocase
        $davroot = "DavWWWRoot" ascii wide nocase
        $wscript = "wscript.exe" ascii wide nocase
        $wsh_ext = ".wsh" ascii wide nocase
        $lnk_header at 0 and $webdav_tunnel and ($davroot or $wsh_ext) and $wscript
rule NuttenTunnel_JSDropper_ActiveX {
        description = "Detects JScript dropper using ActiveXObject to fetch payloads from WebDAV"
        hash = "354e069edf6d52b43326a8f6408e95c0bd4c5cb6da3a81971036e18f8b2ca8c6"
        $ax_shell = "ActiveXObject(\"WScript.Shell\")" ascii
        $ax_fso = "ActiveXObject(\"Scripting.FileSystemObject\")" ascii
        $copyfile = "CopyFile" ascii
        $davroot = "DavWWWRoot" ascii
        $trycloudflare = "trycloudflare.com" ascii
        $ax_shell and $ax_fso and $copyfile and ($davroot or $trycloudflare)
rule NuttenTunnel_BATInstaller {
        description = "Detects batch installer that downloads Python and runs encrypted shellcode loader"
        hash = "ea4043b07992e4aefb3e15b2ef3ddd71de315109c01b4230585cc213ab6ec3dd"
        $path1 = "Microsoft\\Windows\\Crypto\\RSA\\Cache" ascii nocase
        $python_embed = "python-" ascii
        $python_embed2 = "-embed-" ascii
        $encrypted_loader = "encrypted_loader.py" ascii
        $as_encrypted = "as_encrypted.bin" ascii
        $as_key = "as_key.bin" ascii
        $shellcode_banner = "Encrypted Shellcode Loader" ascii
        $invoke_webrequest = "Invoke-WebRequest" ascii nocase
rule NuttenTunnel_PythonShellcodeInjector {
        description = "Detects Python-based AES-256-CBC shellcode decryptor and process injector"
        hash = "4a510219ffc0f5bc4acdf6e33d80d85d88155d88049cedaa00aaa9eed8051a3f"
        $desc = "Encrypted Shellcode Injector" ascii
        $api4 = "OpenProcess" ascii
        $aes = "AES" ascii
        $cbc = "CBC" ascii
        $key_size = "48 bytes" ascii
        $import_ctypes = "import ctypes" ascii
        $process_inject = "ProcessInjector" ascii
        $import_ctypes and $process_inject and 2 of ($api*)
rule NuttenTunnel_WSH_Loader {
        description = "Detects WSH settings file pointing to trycloudflare WebDAV payload"
        hash = "a6a2de606b094f7c4d35cd7cb02f5a512f72981110981fab2bf737ad52bc4506"
        $section = "[ScriptFile]" ascii
        $path = "trycloudflare.com@SSL" ascii nocase
        $timeout = "Timeout=0" ascii
        $section and $path and $timeout
rule NuttenTunnel_Persistence_CryptoLoader {
        description = "Detects persistence mechanism creating CryptoLoader.lnk in Startup"
        hash = "717bb7be812fe4f57d4b7f1add1654b8a2dfb6063bd616cc26748039f247c43f"
        $shortcut = "CryptoLoader.lnk" ascii wide
        $cache_path = "Crypto\\RSA\\Cache" ascii nocase
        $loader = "encrypted_loader.py" ascii
        $payload = "as_encrypted.bin" ascii
        $startup = "Programs\\Startup" ascii nocase
rule Generic_TryCloudflare_WebDAV_Abuse {
        description = "Generic detection for scripts abusing trycloudflare.com via WebDAV"
        $tunnel = "trycloudflare.com" ascii wide nocase
        $webdav1 = "@SSL\\DavWWWRoot" ascii wide nocase
        $webdav2 = "@SSL/DavWWWRoot" ascii wide nocase
        $wscript = "WScript" ascii
        $run = ".Run(" ascii
        $tunnel and ($webdav1 or $webdav2) and 2 of ($ax, $wscript, $copyfile, $run)
rule VOICETRAP_Builder_A_Voicemessage_BAT {
        description = "Detects VOICETRAP polymorphic voicemessage.bat builder variants that use variable splitting to reconstruct TryCloudflare URLs and PowerShell commands, embed M4A decoy audio, and execute via VBScript"
        hash1 = "3877ef81288520aca410885207b0647c79955655adb023a0c50df0255a8e8b00"
        hash2 = "2bedd77cc5402b2a151ae4f4d9743dbdd12d6368ac16dcf86678bd185315957e"
        hash3 = "9a5af44af5dcf614cecb9d6a14f1412e6e59355b980dd1c28325aa3c31de24a1"
        $decoy_msg = "Preparing to decode audiomessage" ascii nocase
        $var_lnk = /set\s+"lnk_\d+_\w+=/ ascii
        $var_dlcmd = /set\s+"dlcmd_\d+_\w+=/ ascii
        $trycloudflare_frag1 = "trycl" ascii
        $trycloudflare_frag2 = "oudfl" ascii
        $trycloudflare_frag3 = "are.c" ascii
        $vbs_b64_decode = "MSXml2.DOMDocument" ascii nocase
        $vbs_adodb = "ADODB.Stream" ascii nocase
        $vbs_savefile = "SaveToFile" ascii nocase
        $m4a_extension = ".m4a" ascii
        $cooltoken = "COOLTOKEN=hello" ascii
        $ps_hidden = "WindowStyle" ascii
        $ps_bypass = "Bypass" ascii
        $iex_pipe = "IEX" ascii
        $b64_header = "AAAA" ascii
        $enabledelayed = "ENABLEDELAYEDEXPANSION" ascii
        $enabledelayed and
        $decoy_msg and
        (2 of ($var_lnk, $var_dlcmd, $cooltoken)) and
        (2 of ($trycloudflare_frag1, $trycloudflare_frag2, $trycloudflare_frag3)) and
        (2 of ($vbs_b64_decode, $vbs_adodb, $vbs_savefile)) and
        $m4a_extension
rule VOICETRAP_Archive_Delivery_ZIP {
        description = "Detects ZIP archives used to deliver VOICETRAP voicemessage.bat payloads"
        hash1 = "2398777300109d63232b61605ac9fe66ce4c92d0bca2465b1a0ed78f5f6ec296"
        hash2 = "70b122b22d71af926931bb91360eabba7d4c3ab1672b4ac60955c33ecb904e2f"
        $pk_header = { 50 4B 03 04 }
        $bat_name = "voicemessage.bat" ascii
        $pk_header at 0 and
        $bat_name and
        filesize < 60KB
rule VOICETRAP_M4A_Decoy_Audio {
        description = "Detects the specific M4A decoy audio file embedded in all VOICETRAP voicemessage.bat variants"
        hash = "d11d8bc2f78520fb6b7bb7d3173597787654a56faa51768246fdd76143046fce"
        $ftyp = { 00 00 00 1C 66 74 79 70 4D 34 41 20 }
        $ftyp at 0 and
        filesize == 21636
rule VOICETRAP_BAT_Variable_Splitting {
        description = "Generic detection for batch files using variable splitting obfuscation pattern (lnk_N_ and dlcmd_N_ prefixes) commonly seen in TryCloudflare malware delivery"
        $lnk_pattern = /set\s+"lnk_\d+_[A-Za-z]+=/ ascii
        $dlcmd_pattern = /set\s+"dlcmd_\d+_[A-Za-z]+=/ ascii
        $ps1_url_reassembly = "ps1_url=" ascii
        $delayed_expansion = "ENABLEDELAYEDEXPANSION" ascii
        $delayed_expansion and
        $ps1_url_reassembly and
        (#lnk_pattern > 5 and #dlcmd_pattern > 10)
rule SERPENTINECLOUD_Python_Shellcode_Loader_BAT {
        description = "Detects SERPENTINE#CLOUD / VOID#GEIST batch-based Python shellcode loader that downloads Python embedded, installs crypto packages, and runs encrypted_loader.py"
        $install_path = "\\Windows\\Crypto\\RSA\\Cache" ascii
        $pip_pyaes = "pip install pyaes" ascii
        $pip_crypto = "pip install cryptography" ascii
        $shellcode_echo = "Encrypted Shellcode Loader" ascii
        $python_embed = "python_embed.zip" ascii
        filesize < 20KB and
rule CVE_2026_21509_ShellExplorer_OLE {
        description = "Detects CVE-2026-21509 exploit documents using Shell.Explorer.1 OLE object"
        hash1 = "8e53683133e7e1ddd1d8728b6ba8b9b80ec40f6772422c8adc8002bafe553f7b"
        hash2 = "520270adf2f2f69021713dfaf5c961d88ba8b06a54d85c68b73bc590ef0ef206"
        // Shell.Explorer.1 CLSID: {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}
        $clsid_bin = { C3 2A B2 EA C1 30 CF 11 A7 EB 00 00 C0 5B AE 0B }
        // RTF hex encoding of CLSID (no whitespace)
        $clsid_rtf = "c32ab2eac130cf11a7eb0000c05bae0b" ascii nocase
        // WebBrowser CLSID (variant): {8856F961-340A-11D0-A96B-00C04FD705A2}
        $clsid_wb_bin = { 61 F9 56 88 0A 34 D0 11 A9 6B 00 C0 4F D7 05 A2 }
        // RTF markers
        $rtf_header = "{\\rtf1" ascii
        // OLE markers
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
        // ActiveX in DOCX
        $activex_classid = "8856F961-340A-11D0-A96B-00C04FD705A2" ascii nocase
        ($rtf_header at 0 and ($clsid_bin or $clsid_rtf)) or
        ($ole_header at 0 and $clsid_bin) or
        ($activex_classid)
rule CVE_2026_21509_IndianAPT_WarMachine {
        description = "Detects documents from the WarMachine/MALDEV01 Indian APT developer targeting Pakistan"
        hash = "8e53683133e7e1ddd1d8728b6ba8b9b80ec40f6772422c8adc8002bafe553f7b"
        $machine_utf16 = "MALDEV01" wide
        $user_utf16 = "WarMachine" wide
        $user_short = "WarMac" wide
        $author = "MALDE" wide
        $wps_build = "WPS Office_12.2.0.23196" wide
        $wps_uuid = "F1E327BC-269C-435d-A152-05C5408002CA" ascii wide
        $psca_url = "psca.gop.pk" ascii wide
        $pdf_path = "PDF-READER" ascii wide
        $siehs = "SIEHS" ascii wide nocase
        uint32(0) == 0xE011CFD0 and (
            ($machine_utf16 and $user_utf16) or
            ($machine_utf16 and $author) or
            ($psca_url) or
            ($wps_build and any of ($machine_utf16, $user_utf16, $author)) or
            3 of them
rule CVE_2026_21509_RTF_IndiaLocale {
        description = "Detects CVE-2026-21509 RTF exploits with English-India locale and Shell.Explorer.1 OLE"
        hash1 = "520270adf2f2f69021713dfaf5c961d88ba8b06a54d85c68b73bc590ef0ef206"
        hash2 = "b68e729104d051eaf3d118f9fd9c3fde81255f2b14f349a9ce421423407e5a77"
        $rtf = "{\\rtf1" ascii
        $deflang_india = "deflang19465" ascii
        $adeflang_arabic = "adeflang1025" ascii
        $objocx = "\\objocx" ascii
        $objemb = "\\objemb" ascii
        $ole_magic = "D0CF11E0A1B11AE1" ascii nocase
        $file_class = "objclass file" ascii
        $webdav_lnk = ".LnK" ascii nocase
        $rtf at 0 and $deflang_india and $objocx and $ole_magic and
        ($file_class or $webdav_lnk)
rule CVE_2026_21509_WebDAV_LNK_Fetch {
        description = "Detects CVE-2026-21509 documents fetching LNK files via WebDAV (file:// protocol)"
        $file_proto = "file://" ascii wide
        $lnk_ext = ".LnK" ascii wide nocase
        $init_param = "?init=1" ascii wide
        $ssl_webdav = "@ssl/" ascii wide
        $clsid_shell = { C3 2A B2 EA C1 30 CF 11 A7 EB 00 00 C0 5B AE 0B }
        $clsid_wb = { 61 F9 56 88 0A 34 D0 11 A9 6B 00 C0 4F D7 05 A2 }
        ($file_proto and $lnk_ext and $init_param) or
        ($file_proto and $ssl_webdav and ($clsid_shell or $clsid_wb)) or
        ($file_proto and $lnk_ext and ($clsid_shell or $clsid_wb))
rule Mirzbow_LNK_BitsAdmin_Dropper {
        description = "Detects LNK files using caret-obfuscated BitsAdmin to download from 46.161.0.94"
        hash = "ce01596c7e57752e28c9c6ed1102afde6b5ea9e1084e5d79fd3cdd2afdda819e"
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $bits1 = "b^i^t^s^a^d^m^i^n" ascii wide nocase
        $bits2 = "bitsadmin" ascii wide nocase
        $c2_ip = "46.161.0.94" ascii wide
        $hta = "artifactperformance.hta" ascii wide nocase
        $mirzbow = "Mirzbow" ascii wide
        $mshta = "mshta" ascii wide nocase
        $delayed = "/v:on" ascii wide nocase
        $lnk_magic at 0 and $c2_ip and (1 of ($bits*) or $mshta or $hta or $mirzbow)
rule Mirzbow_LNK_PowerShell_Dropper {
        description = "Detects LNK files using PowerShell with UA WindowsPowerShell to download from C2"
        hash = "8d67ee22dd5b1ad0ba524b46691f988240785c67a6ba3901c41945823f6c1c87"
        $ua = "UA WindowsPowerShell" ascii wide
        $winhttpreq = "WinHttp.WinHttpRequest" ascii wide nocase
        $scriptblock = "ScriptBlock" ascii wide
        $hidden = "-w Hidden" ascii wide nocase
        $mirmLAT = "mirmLAT" ascii wide
        $smersh = "smersh" ascii wide
        $lnk_magic at 0 and ($c2_ip or $ua) and (1 of ($winhttpreq, $scriptblock, $mirmLAT, $smersh))
rule Mirzbow_LNK_ChromeUpdate_MultiStage {
        description = "Detects LNK files downloading trojanized chrome.exe with string-split obfuscation"
        hash = "adf20c2868817140956045bc75a348a2170d2ecf58ef83758e2ca5688581e0b4"
        $chromeupd = "chromeupd" ascii wide nocase
        $ps_x32 = "ps_x32" ascii wide
        $expand = "Expand-Archive" ascii wide nocase
        $split_http = "htt''p" ascii wide
        $split_ip1 = "46''.16" ascii wide
        $wildcard_cmd = "inv??e-webr" ascii wide nocase
        $decoy = "unarchive_attempt_failure" ascii wide
        $lnk_magic at 0 and (2 of ($chromeupd, $ps_x32, $expand, $decoy) or 2 of ($split_http, $split_ip1, $wildcard_cmd) or $c2_ip)
rule Mirzbow_Campaign_ZIP_Container {
        description = "Detects ZIP files containing Mirzbow campaign LNK droppers"
        hash = "3c5ca1d037d3d3ac89fb1415a4b374e4ead9f36c466b7917fa4f009e0a834b5f"
        $zip_magic = { 50 4B 03 04 }
        $lnk_ext1 = ".xlsx.lnk" ascii wide nocase
        $lnk_ext2 = ".xls.lnk" ascii wide nocase
        $lnk_ext3 = ".rtf.lnk" ascii wide nocase
        $bits = "bitsadmin" ascii wide nocase
        $zip_magic at 0 and filesize < 50KB and (1 of ($lnk_ext*) and (1 of ($c2_ip, $bits, $ua)))
rule Bigpanzi_Pandoraspear_Backdoor {
        description = "Detects Bigpanzi Pandoraspear ELF backdoor targeting Android TV boxes"
        hash_md5 = "9a1a6d484297a4e5d6249253f216ed69"
        $upx_magic = { 71 28 40 75 }
        $blowfish_key = "zAw2xidjP3eHQ" ascii
        $c2_port = ":9999" ascii
        $hosts_path = "/data/.hosts" ascii
        $ms_path = "/data/.ms" ascii
        $pandora1 = "pandoraspear" ascii nocase
        $pandora2 = "panddna" ascii
        $pandora3 = "mf1ve" ascii
        $pandora4 = "mflve" ascii
        $pandora5 = "pnddon" ascii
        $pandora6 = "bsaldo" ascii
        $pandora7 = "pdonno" ascii
        $pandora8 = "pdltdgie" ascii
        (uint32(0) == 0x464C457F) and
            $upx_magic or
            $blowfish_key or
            (2 of ($pandora*)) or
            ($hosts_path and $ms_path) or
            ($c2_port and 1 of ($pandora*))
rule Bigpanzi_Pcdn_Module {
        description = "Detects Bigpanzi Pcdn P2P CDN and DDoS module"
        hash_md5 = "7ccdaa9aa63114ab42d49f3fe81519d9"
        $pcdn1 = "pcdnbus" ascii
        $pcdn2 = "ou2sv.com" ascii
        $pcdn3 = "a2k3v.com" ascii
        $pcdn4 = "snarutox" ascii
        $pcdn5 = "oneconcord" ascii
        $pcdn6 = "trumpary" ascii
        $pcdn7 = "fireisi" ascii
        $pcdn8 = "ourhousei" ascii
        $port1 = ":31226" ascii
        $port2 = ":19906" ascii
        $port3 = ":7172" ascii
        $getstatus = "/getstatus" ascii
            (2 of ($pcdn*)) or
            ($getstatus and 1 of ($port*)) or
            (2 of ($port*))
rule Kimwolf_Bot_ELF {
        description = "Detects Kimwolf Mirai-derivative DDoS bot targeting Android TV"
        $socket_name = "@niggaboxv" ascii
        $ens_domain = "pawsatyou" ascii
        $signer = "Dinglenut" ascii
        $c2_1 = "14emeliaterrace" ascii
        $c2_2 = "samsungcdn.cloud" ascii
        $c2_3 = "proxiessdk" ascii
        $c2_4 = "groksearch" ascii
        $c2_5 = "pproxy1.fun" ascii
        $krebs = "fuckbriankrebs" ascii
        $krebs2 = "krebsfiveheadindustries" ascii
            $socket_name or
            $ens_domain or
            (2 of ($c2_*)) or
            1 of ($krebs*)
rule Kimwolf_Bot_APK {
        description = "Detects Kimwolf trojanized Android APK (signed with known cert)"
        cert_fingerprint = "182256bca46a5c02def26550a154561ec5b2b983"
        $cert_cn = "John Dinglebert Dinglenut VIII VanSack Smith" ascii wide
        $socket = "niggaboxv" ascii
        $ens = "pawsatyou" ascii
        $proxy_sdk = "proxiessdk" ascii
        $byte_connect = "ByteConnect" ascii wide
            $cert_cn or
            ($socket and $ens) or
            ($proxy_sdk or $byte_connect)
rule ChanMirai_C2_Domain {
        description = "Detects ChanMirai botnet C2 domain strings in binaries"
        $domain1 = "chanmiraicd1.duckdns.org" ascii wide nocase
        $domain2 = "chanmiraicd1" ascii wide nocase
        $url1 = "/bot_x86" ascii wide
        $url2 = "/bot_x86.exe" ascii wide
        $ip1 = "185.242.3.231" ascii wide
rule ChanMirai_Bot_Strings {
        description = "Detects potential ChanMirai Mirai variant by infrastructure strings"
        $c2_domain = "chanmiraicd1.duckdns.org" ascii wide nocase
        $c2_ip = "185.242.3.231" ascii wide
        // Common Mirai variant strings
        $mirai1 = "/bin/busybox" ascii
        $mirai2 = "LZRD" ascii  // Common Mirai variant marker
        $mirai3 = "SATORI" ascii
        $mirai4 = "/tmp/" ascii
        $scanner1 = "TSource Engine Query" ascii  // Mirai DDoS UDP payload
        $scanner2 = "/etc/resolv.conf" ascii
        ($c2_domain or $c2_ip) and
        2 of ($mirai*, $scanner*)
rule Mirai_CNC_HighPort_Config {
        description = "Detects Mirai variants configured to use high port ranges (30000+) for CNC"
        $port_30000 = { 75 30 }  // Port 30000 in big-endian
        $port_31337 = { 7A 69 }  // Port 31337 in big-endian
        $port_32000 = { 7D 00 }  // Port 32000 in big-endian
        $duckdns = "duckdns.org" ascii wide nocase
        $mirai_killer = "killer" ascii  // Mirai process killer module
        $mirai_scanner = "scanner" ascii
        $busybox = "/bin/busybox" ascii
        uint32(0) == 0x464C457F and
        $duckdns and
        1 of ($port_*) and
        1 of ($mirai_*, $busybox)
rule HOSTING_SEO_Phishing_Kit_HTML {
        description = "Detects HOSTING///SEO phishing kit HTML pages"
        $title1 = "HOSTING///SEO" ascii wide
        $title2 = "| HOSTING///SEO" ascii wide
        $path1 = "/checkout/" ascii
        $path2 = "/track/" ascii
        $less1 = "/less/" ascii
        $less2 = ".1728466216.css" ascii
        $less3 = ".1728720195.css" ascii
        $less4 = ".1728719825.css" ascii
        $less5 = ".1728720622.css" ascii
        $vue = "vue/2.6.11/vue.min.js" ascii
        $paypal = "AS3CsnJh4pP09uP1G8exc1fLHmjRLiUSvtkwR0ta-sqNSVwTUCh6HlltvKS7V4TS89YfVy8Y5i1zDJaD" ascii
        $iconify = "iconify.design/1/1.0.4/iconify.min.js" ascii
        $title1 or $paypal or (2 of ($less*)) or ($title2 and $vue) or ($path1 and $path2 and $iconify)
rule HOSTING_SEO_FingerprintJS_Redirect {
        description = "Detects HOSTING///SEO FingerprintJS evasion redirect page"
        $fp1 = "FingerprintJS.load" ascii
        $fp2 = "result.visitorId" ascii
        $rdr1 = "redirect_link" ascii
        $rdr2 = "tr_uuid=" ascii
        $rdr3 = "fp=-7" ascii
        $bg = "background:#101c36" ascii
        ($fp1 and $fp2 and $rdr2) or ($rdr1 and $rdr2 and $rdr3) or ($bg and $fp1)
rule HOSTING_SEO_CSS_Artifact {
        description = "Detects HOSTING///SEO kit CSS timestamp artifacts from October 2024 development"
        $css1 = "0901a2ad17c2778ebb6fed023ba31795" ascii
        $css2 = "19019e164f906ebcbb7f8f707444b89e" ascii
        $css3 = "5dd4c698961ce2925c740be6d7c62e0f" ascii
        $css4 = "3a2ccc51113bc8af97513d07138b09da" ascii
        $css5 = "2633d35b24cbda924d76f09795eb1b20" ascii
rule SUSP_ELF_Modified_UPX_OPS_Magic {
        description = "Detects ELF binaries packed with UPX where the magic bytes have been changed from UPX! to OPS! - a technique used by both IoT botnets and some legitimate firmware build tools. Requires additional context to determine malicious intent."
        hash = "6439834bec1cc530b12b1d821a509561efdd43048ecfb183939fe00a11a3c7dd"
        false_positive = "OpenPLC Editor Arduino firmware builds"
        $ops_magic = "OPS!" ascii
        $upx_info = "$Info: This file is packed with the UPX executable packer" ascii
        $upx_id = "$Id: UPX" ascii
        #ops_magic >= 1 and
        ($upx_info or $upx_id) and
        not "UPX!" ascii
rule SUSP_ELF_UPX_Magic_Substitution_Generic {
        description = "Detects ELF binaries with UPX info strings but where the standard UPX! magic has been replaced with any other 4-byte value. Covers all known magic byte substitutions used by Mirai, Gafgyt, and other IoT botnet families."
        $upx_std = "UPX!" ascii
        not $upx_std
rule OpenPLC_Arduino_Firmware {
        description = "Detects OpenPLC Editor firmware compiled for Arduino platforms. Use as a whitelist/exclusion rule to reduce false positives on UPX-packed ARM ELF binaries."
        reference = "https://github.com/thiagoralves/OpenPLC_Editor"
        $openplc1 = "OpenPLC_Editor" ascii
        $openplc2 = "openplc.h" ascii
        $plc_func1 = "plcCycleTask" ascii
        $plc_func2 = "glueVars" ascii
        $plc_func3 = "updateInputBuffers" ascii
        $plc_func4 = "updateOutputBuffers" ascii
        $modbus1 = "ModbusSlave" ascii
        $modbus2 = "MB_FC_READ_COILS" ascii
        $arduino1 = "Baremetal.ino" ascii
        $arduino2 = "arduino-sketch-" ascii
        ($openplc1 or $openplc2) and
        2 of ($plc_func*) and
        1 of ($modbus*) and
        1 of ($arduino*)
rule Smile_Admin_Panel_HTML {
        description = "Detects HTML responses from the Smile Admin fraud panel (Laravel/Inertia.js)"
        reference = "Breakglass Intelligence - Smile Admin Panel Investigation"
        $title = "<title inertia>Smile Admin</title>" ascii
        $session = "smile_admin_session" ascii
        $route1 = "cookiesjson" ascii
        $route2 = "wallettransaction" ascii
        $route3 = "updateMmkPrice" ascii
        $route4 = "cookiesjsonupdate" ascii
        $domain1 = "crazydazy.online" ascii
        $domain2 = "skibidispace.xyz" ascii
        $ziggy = "const Ziggy=" ascii
        $inertia = "X-Inertia" ascii
        $title or
        ($session and any of ($route*)) or
        (any of ($domain*) and any of ($route*)) or
        ($ziggy and $route1 and $route2)
rule Smile_Admin_Cookie_Exfil {
        description = "Detects cookie exfiltration payloads targeting Smile Admin panel endpoints"
        $endpoint1 = "/cookiesjson" ascii wide
        $endpoint2 = "/cookiesjsonupdate" ascii wide
        $domain1 = "crazydazy.online" ascii wide
        $domain2 = "skibidispace.xyz" ascii wide
        $smile = "smile.crazydazy" ascii wide
        $smile2 = "smile.skibidispace" ascii wide
        any of ($endpoint*) and any of ($domain*, $smile, $smile2)
rule Smile_OMG_GameShop_Frontend {
        description = "Detects the OMG GameShop frontend associated with Myanmar-targeted fraud"
        $title = "OMG - GameShop" ascii
        $font = "Noto+Sans+Myanmar" ascii
        $framework = "create-tsrouter-app" ascii
        $domain = "crazydazy.online" ascii wide
        $title or ($font and $framework) or ($title and $domain)
rule Amadey_Cred64_Plugin {
        description = "Amadey botnet credential stealer plugin (cred64.dll) targeting browsers, email, FTP, crypto wallets"
        hash = "a410c89db9140ed9dff55bff00b0338fbdffcc709490782c7b28e8a10c11eb3b"
        $export_main = "Main" ascii
        $export_save = "Save" ascii
        $s_cred_param = "&cred=" ascii
        $s_filezilla = "FileZilla\\sitemanager.xml" ascii wide
        $s_monero1 = "Monero\\wallets\\" ascii wide
        $s_monero2 = "monero-wallet-gui" ascii wide
        $s_gajim = "\\Gajim\\Settings.sqlite" ascii wide
        $s_thunderbird = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Thunderbird.exe" ascii wide
        $s_firefox_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" ascii wide
        $s_logins = "\\logins.json" ascii wide
        $s_encrypted_pw = "\"encryptedPassword\":\"([^\"]+)\"" ascii
        $s_encrypted_un = "\"encryptedUsername\":\"([^\"]+)\"" ascii
        $s_winscp = "WinSCP.exe" ascii wide
        $s_imap_pw = "IMAP Password" ascii wide
        $s_smtp_pw = "SMTP Password" ascii wide
        $s_pop3_pw = "POP3 Password" ascii wide
        $api_dpapi = "CryptUnprotectData" ascii
        $api_bcrypt = "BCryptDecrypt" ascii
        $api_http = "HttpSendRequestA" ascii
        all of ($export_*) and
        $api_dpapi and
        $api_bcrypt and
        3 of ($s_*)
rule Amadey_Cred64_Imphash {
        description = "Amadey cred64.dll detection by import hash"
        pe.imphash() == "3f175edea93fa7a76a78004d12de2235"
rule Amadey_Panel_Path_Artifact {
        description = "Detects Amadey panel path artifacts in memory or network captures"
        $path1 = "/g8hrS4f4vh/index.php" ascii wide nocase
        $path2 = "/g8hrS4f4vh/Login.php" ascii wide nocase
        $path3 = "/g8hrS4f4vh/" ascii wide nocase
        $amadey_cred = "&cred=" ascii
        $amadey_id = "&id=" ascii
        $amadey_vs = "&vs=" ascii
        $amadey_sd = "&sd=" ascii
        $amadey_os = "&os=" ascii
        $amadey_bi = "&bi=" ascii
        $amadey_ar = "&ar=" ascii
        any of ($path*) or
        (4 of ($amadey_*))
rule CRPX0_Clipper_Payload {
        description = "Detects CRPX0/DataBreachPlus cryptocurrency clipboard hijacker payload"
        $api1 = "fanonlyatn.xyz" ascii wide
        $api2 = "api_address_match.php" ascii wide
        $api3 = "26i$MyYe@r" ascii wide
        $secret = "API_CONFIG_SECRET" ascii
        $class1 = "CryptoGuard" ascii
        $class2 = "AutoEnvironment" ascii
        $func1 = "monitor_clipboard_changes" ascii
        $func2 = "detect_crypto_address" ascii
        $func3 = "detect_seed_phrases" ascii
        $func4 = "get_matching_address_from_api" ascii
        $func5 = "send_install_heartbeat" ascii
        $wallet_btc = "1KC2kXDeyBH9yocYSQy6DQ1ou5hRRRBtpZ" ascii
        $wallet_eth = "0x835270cEd14bfdAaeF8F8Fa0e532A244cfDe8b52" ascii
        $wallet_tron = "TDtxY9ZHNffj14Ci9qhBjkpR2AAhCaHuXs" ascii
        $wallet_sol = "FQPxYxm4y7D6PFjFcGeKcPe42kUfbDnbRsaeLoPYmxYQ" ascii
        $build = "BUILD_ID" ascii
        $agent = "AGENT_ID" ascii
        $hidden = ".sys32data" ascii
        (2 of ($api*)) or
        ($class1 and 2 of ($func*)) or
        (2 of ($wallet*)) or
        ($hidden and $build and $agent and 1 of ($func*))
rule CRPX0_Ransomware {
        description = "Detects CRPX0/DataBreachPlus ransomware module"
        $ext = ".crpx0" ascii wide
        $note = "HOW TO RECOVER" ascii wide
        $opid = "OP-" ascii
        $ua = "crpx0-client/1.0" ascii
        $c2_1 = "caribb.ru/crpx0" ascii
        $c2_2 = "mekhovaya-shuba.ru/crpx0" ascii
        $c2_3 = "beboss34.ru/crpx0" ascii
        $c2_4 = "notify.php" ascii
        $tg = "DataBreachPlus" ascii
        $email = "databreachplus@proton.me" ascii
        $qtox = "17EB54B8455144E088C7E77F88A97221C319F0CFE4FE306853EEB113EE8DB5607BB6EE481C7C" ascii
        $func1 = "stage1_scan" ascii
        $func2 = "stage2_encrypt" ascii
        $func3 = "remove_backups" ascii
        $func4 = "ENCRYPTED_EXT" ascii
        $secret = "DASHBOARD_SECRET" ascii
        ($ext and 2 of ($c2_*)) or
        ($ext and $note and 1 of ($func*)) or
        ($tg and ($email or $qtox) and $ext) or
        (3 of ($c2_*)) or
        ($ua and $ext)
rule CRPX0_SeedFinder {
        description = "Detects CRPX0/DataBreachPlus BIP39 seed phrase scanner"
        $class = "SeedFinder" ascii
        $func1 = "detect_seed_phrases" ascii
        $func2 = "scan_file" ascii
        $func3 = "register_client" ascii
        $build = "ULTRA_STRICT" ascii
        $domain = "fanonlyatn.xyz" ascii
        $api = "api.php" ascii
        $secret = "26i$MyYe@r" ascii
        ($class and 2 of ($func*)) or
        ($domain and $api and $class) or
        ($secret and $class)
rule CRPX0_Installer {
        description = "Detects CRPX0/DataBreachPlus stage 2 installer (call2.py)"
        $dir = "sys32data" ascii
        $file = "sys32.py" ascii
        $builds = "/builds/last.zip" ascii
        $scanner = "/builds/scan/finderx.zip" ascii
        $plist = "com.sys32.data" ascii
        $func = "_background_setup" ascii
        $log = "call2_debug.txt" ascii
        ($dir and $file and $domain) or
        ($builds and $scanner) or
        ($plist and $domain) or
        ($func and $log and $dir)
rule CRPX0_MacOS_Loader {
        description = "Detects CRPX0/DataBreachPlus macOS loader scripts"
        $dir = ".sys32data" ascii
        $pass = "pass2021#" ascii
        $fedex = "FedEx Secure Access" ascii
        $onlyfans = "OnlyFans Secure Archive" ascii
        $python = "python-build-standalone" ascii
        $call2 = "call2.py" ascii
        $builder1 = "mac_app_builder" ascii
        $builder2 = "mac_pkg_builder" ascii
        $builder3 = "mac_pro_builder" ascii
        $builder4 = "mac_vault_builder" ascii
        $builder5 = "mac_ultimate_builder" ascii
        ($domain and ($dir or $call2)) or
        ($pass and ($fedex or $onlyfans)) or
        ($domain and 1 of ($builder*))
rule MacSync_Stealer_MachO {
        description = "Detects MacSync Stealer Mach-O binaries signed by OKAN ATAKOL"
        hash = "06c74829d8eee3c47e17d01c41361d314f12277d899cc9dfa789fe767c03693e"
        $dev_id = "OKAN ATAKOL" ascii
        $team_id = "GNJLS3UYZ4" ascii
        $dev_cert = "Developer ID Application" ascii
        $curl_noproxy = "--noproxy '*'" ascii
        $tls_strict = "--tlsv1.2 --tls-max 1.3" ascii
        $check_inet = "checkInternet" ascii
        $is_script = "isScript" ascii
        $tool_arm = "tool_arm64" ascii
        $tool_x86 = "tool_x86_64" ascii
        $c2_domain = "gatemaden.space" ascii
        $curl_path = "/usr/bin/curl" ascii
        $url_session = "NSURLSession" ascii
        $file_handle = "fileHandleForWritingToURL" ascii
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xBEBAFECA or uint32(0) == 0xCAFEBABE) and
            ($dev_id and $team_id) or
            ($c2_domain) or
            ($curl_noproxy and $tls_strict and ($tool_arm or $tool_x86)) or
            ($check_inet and $is_script and $url_session and $file_handle) or
            (3 of ($curl_noproxy, $tls_strict, $check_inet, $is_script, $curl_path, $url_session))
rule MacSync_C2_Panel_JS {
        description = "Detects MacSync Stealer C2 panel JavaScript bundle"
        hash = "c30821f32344e2e1db5a1b22280e5f1fa0612c78da24710cf6af8bd22bd0ce41"
        $api1 = "/api/v1/auth/download-wallets" ascii
        $api2 = "/api/v1/auth/download-without-wallets" ascii
        $api3 = "/api/v1/auth/restore-cookies" ascii
        $api4 = "/api/v1/auth/bot-actions" ascii
        $api5 = "/api/v1/admin/safe-exit" ascii
        $api6 = "/api/v1/auth/create-guest-link" ascii
        $api7 = "/api/v1/auth/repeat-all" ascii
        $ru1 = { 41 0434 043C 0438 043D 0020 043F 0430 043D 0435 043B 044C } // "Админ панель" in UTF-8
        $ru_builder = "\"builder\":\"\\u0411\\u0438\\u043b\\u0434\\u0435\\u0440\"" ascii
        $str1 = "Repeat Stealer" ascii
        $str2 = "FileGrabber" ascii
        $str3 = "Cryptochecker" ascii
        $str4 = "SAFE EXIT" ascii
        $str5 = "Download only with Wallets" ascii
        $str6 = "Application wants to install helper" ascii
        $str7 = "chatIdLedger" ascii
        $str8 = "chatIdCrypto" ascii
        filesize > 500KB and
        (4 of ($api*) or (2 of ($api*) and 3 of ($str*)))
rule MacSync_ClickFix_ZIP {
        description = "Detects MacSync Stealer ClickFix delivery ZIP/DMG packages"
        $trezor = "Trezor Suite" ascii wide
        $ledger = "Ledger Live" ascii wide
        $zoom = "Zoom" ascii wide
        $okan = "OKAN ATAKOL" ascii
        $team = "GNJLS3UYZ4" ascii
        $gatemaden = "gatemaden.space" ascii
        $noproxy = "--noproxy" ascii
        (uint16(0) == 0x4B50 or uint32(0) == 0x6B6F6F63) and
        ($okan or $team or $gatemaden) and
        any of ($trezor, $ledger, $zoom)
rule SheetRAT_DotNET_Variant {
        description = "Detects SheetRAT .NET RAT variants (VenomRAT lineage) with character substitution obfuscation"
        hash = "178dcffa7899bf9955bf12c4eefada6f635972f59f5531b53ff9e6da96293d9c"
        reference = "https://intel.breakglass.tech/post/nexus-phish"
        $dotnet = ".NETFramework,Version=v4.0" ascii
        $s1 = "DynamicAPIInvoke" ascii
        $s2 = "PatchETW" ascii wide
        $s3 = "AsmiAndETW" ascii
        $s4 = "ExclusionWD" ascii
        $s5 = "ProcessClientBufferReceived" ascii
        $s6 = "ProcessClientBufferNotReceived" ascii
        $s7 = "MutexControl" ascii
        $s8 = "UseInstallAdmin" ascii
        $s9 = "InstallWatchDog" ascii
        $s10 = "CheckWMI" ascii
        $s11 = "SslClient" ascii
        $s12 = "ValidateServerCertificate" ascii
        $s13 = "LEB128" ascii
        $rootkit = "%RootKit%" ascii wide
        $obf1 = "9=wwQ:N" wide
        $obf2 = "r^wi6l" wide
        $obf3 = "3^{Nm.y" wide
        $hex1 = "E123F60E9FC6E974D1381F2F15FB19E7960628CC8925D65E344C2F2BDC64F424" ascii
        $dotnet and
            (4 of ($s*)) or
            ($rootkit and 2 of ($s*)) or
            (2 of ($obf*) and 2 of ($s*)) or
            ($hex1 and 2 of ($s*))
rule SheetRAT_Generic_Methods {
        description = "Detects SheetRAT by unique combination of method names common to the family"
        $m1 = "DynamicAPIInvoke" ascii
        $m2 = "PatchETW" ascii
        $m3 = "ExclusionWD" ascii
        $m4 = "MutexControl" ascii
        $m5 = "ProcessClientBufferReceived1" ascii
        $m6 = "ProcessClientBufferReceived2" ascii
        $m7 = "ProcessClientBufferNotReceived1" ascii
        $m8 = "GetExportAddress" ascii
        $m9 = "FunctionDelegateType" ascii
        $m10 = "UserINIT" ascii
        $mpe = { 4D 5A }
        $mpe at 0 and filesize < 10MB and 5 of ($m*)
rule Nexus_Phishing_Infrastructure {
        description = "Detects HTML/JS artifacts from Nexus phishing infrastructure"
        $title = "OpenSea Community Rewards" ascii nocase
        $d1 = "claim-opensea.com" ascii nocase
        $d2 = "verifyprotection.com" ascii nocase
        $d3 = "0ffice-signin.com" ascii nocase
        $d4 = "myaccounts-chase.com" ascii nocase
        $d5 = "creditunion-verify.com" ascii nocase
        $d6 = "yahoo-accounts.com" ascii nocase
        $title or 2 of ($d*)
rule Nexus_C2_Panel_HTML {
        description = "Detects Nexus C2 Dashboard HTML content (Android banking trojan panel)"
        $title = "Nexus C2 Dashboard" ascii nocase
        $title2 = "Nexus C2 Control Panel" ascii nocase
        $nav1 = "/admin/data" ascii
        $nav2 = "/admin/commands" ascii
        $stat1 = "Active Bots" ascii
        $stat2 = "Stolen Credentials" ascii
        $stat3 = "Seed Phrases" ascii
        $cmd1 = "lock_screen" ascii
        $cmd2 = "inject" ascii
        $cmd3 = "Inject Overlay" ascii
        $api1 = "/api/register" ascii
        $api2 = "/api/exfil" ascii
        ($title or $title2) and (2 of ($nav*, $stat*, $cmd*, $api*))
rule RodexRMM_HTA_Dropper {
        description = "Detects RodexRMM HTA dropper with triple-fallback download and UAC elevation"
        hash = "69b641635a37fd961410402f8c7e66bd072d51e26f9a6be7d03f185eb344f746"
        $hta_id = "RodexInstaller" ascii
        $dl_url = "/api/agent/download/" ascii
        $ps_bypass = "-ep Bypass -NoProfile -WindowStyle Hidden" ascii
        $wmi_pagefile = "wmic pagefileset" ascii
        $launcher_bat = "RodexLauncher.bat" ascii
        $setup_exe = "RodexSetup.exe" ascii
        $shell_runas = "\"runas\"" ascii
        $winhttp = "WinHttp.WinHttpRequest" ascii
        $self_delete = "oFSO.DeleteFile" ascii
        filesize < 50KB and (
            $hta_id or
            ($dl_url and $setup_exe) or
            (3 of ($ps_bypass, $wmi_pagefile, $launcher_bat, $setup_exe, $shell_runas)) or
            ($winhttp and $self_delete and $setup_exe)
rule RodexRMM_GoLang_Agent {
        description = "Detects RodexRMM GoLang agent binary (core RAT or installer variant)"
        hash1 = "17ef90287357375f65849773176f5da3490080403170ccbdaa1358f3db767d15"
        hash2 = "61cab707c0869212b0ee594da70e668821803db6e9fcb3a3ec8a414dbe80c63e"
        $s1 = "RodexAgent" ascii
        $s2 = "Rodex_helper.log" ascii
        $s3 = "rodex_cmd_%s.ps1" ascii
        $s4 = "Rodex RMM Agent Installer" ascii
        $s5 = "Rodex.RMM.Agent" ascii
        $s6 = "net stop RodexAgent" ascii
        $s7 = "--helper-addr is required with --screen-helper" ascii
        $s8 = "relay going away" ascii
        $s9 = "Sending heartbeat: CPU=" ascii
        $s10 = "[startup] Config: server=%s device=%s heartbeat=%ds relay=%s" ascii
        $s11 = "overlay excluded from screen capture" ascii
        $s12 = "--server and --token are required for --install" ascii
        $go1 = "gopsutil/v3/cpu" ascii
        $go2 = "gopsutil/v3/mem" ascii
        $go3 = "gopsutil/v3/disk" ascii
            3 of ($s*) or
            ($s1 and 2 of ($go*)) or
            ($s5 and any of ($s*))
rule RodexRMM_Config_Artifact {
        description = "Detects RodexRMM agent configuration or artifacts on disk"
        $svc = "RodexAgent" ascii wide
        $log = "Rodex_helper.log" ascii wide
        $cmd = "rodex_cmd_" ascii wide
        $manifest = "Rodex.RMM.Agent" ascii wide
rule PhantomCentre_FakeCloudflareChallenge {
        description = "Detects fake Cloudflare challenge pages used by PHANTOM CENTRE AiTM phishing campaign"
        $title1 = "Attention Required! | Cloudflare" ascii wide
        $title2 = "Secure Authentication Portal" ascii wide
        $title3 = "Security Verification Required" ascii wide
        $title4 = "Access Control Verification" ascii wide
        $title5 = "Account Security Check" ascii wide
        $title6 = "Security Gateway" ascii wide
        $title7 = "Please stand by, while we are checking your browser" ascii wide
        $server = "nginx/1.18.0 (Ubuntu)" ascii
        $cf_css = "cf.errors.css" ascii
        $cf_img = "cf-no-screenshot-error.png" ascii
        any of ($title*) and ($server or any of ($cf*))
rule PhantomCentre_InfraNodeSubdomain {
        description = "Detects PHANTOM CENTRE infrastructure node naming pattern in URLs or certificates"
        $pattern1 = /hub-\d{2}-[a-z]{6}-\d{4}-storage-node-\d{2}/ ascii
        $pattern2 = /svc-\d{2}-[a-z]{6}-\d{4}-digital-hub-\d{2}/ ascii
        $pattern3 = /app-\d{2}-[a-z]{6}-\d{4}-secure-hub-\d{2}/ ascii
        $pattern4 = /core-\d{2}-[a-z]{6}-\d{4}-infra-node-\d{2}/ ascii
        $pattern5 = /secure-\d{2}-[a-z]{6}-\d{4}-data-hub-\d{2}/ ascii
        $pattern6 = /net-\d{2}-[a-z]{6}-\d{4}-data-hub-\d{2}/ ascii
rule PhantomCentre_CampaignDomain {
        description = "Detects PHANTOM CENTRE campaign domain references in network traffic or files"
        $d1 = "inhwabusinesscentre.com" ascii wide nocase
        $d2 = "starbearingcentre.com" ascii wide nocase
        $d3 = "theworkitcentre.com" ascii wide nocase
        $d4 = "countoncopelandcom.cloud" ascii wide nocase
        $d5 = "prjnation.sbs" ascii wide nocase
        $d6 = "vvgks.me" ascii wide nocase
        $d7 = "vantedglelgx.com" ascii wide nocase
        $telemetry1 = "raventelemetry" ascii wide nocase
        $telemetry2 = "raventelemtry" ascii wide nocase
        $telemetry3 = "aventelemetry" ascii wide nocase
        $telemetry4 = "fraventelemetry" ascii wide nocase
        any of ($d*) or any of ($telemetry*)
rule SuperShell_C2_LoginPage {
        description = "Detects SuperShell C2 framework login page HTML"
        $title1 = "Supershell - " ascii wide
        $title2 = "\xe7\x99\xbb\xe5\xbd\x95" ascii  // 登录 (login in Chinese)
        $path1 = "/supershell/login/auth" ascii
        $path2 = "/supershell/login" ascii
        $path3 = "/supershell/monitor" ascii
        $js1 = "login_enter_listen" ascii
        $js2 = "func/login.js" ascii
        $logo = "/static/img/logo.svg" ascii
        $title1 and ($title2 or $path1) and any of ($path*, $js*, $logo)
rule SuperShell_C2_ClientJS {
        description = "Detects SuperShell C2 framework client management JavaScript"
        $func1 = "update_client_memory" ascii
        $func2 = "get_attribution_html" ascii
        $func3 = "show_deleteClient" ascii
        $func4 = "get_os_html" ascii
        $path1 = "/supershell/session/info" ascii
        $path2 = "/supershell/session/shell" ascii
        $path3 = "/supershell/session/memfd" ascii
        $cn1 = "\xe5\x9c\xa8\xe7\xba\xbf" ascii  // 在线 (online)
        $cn2 = "\xe7\xa6\xbb\xe7\xba\xbf" ascii  // 离线 (offline)
        3 of ($func*) or (2 of ($path*) and any of ($cn*))
rule SuperShell_C2_MonitorJS {
        description = "Detects SuperShell C2 framework monitor dashboard JavaScript"
        $func1 = "get_rssh_status" ascii
        $func2 = "get_clients_num" ascii
        $func3 = "get_compiled_num_size" ascii
        $func4 = "get_monitor_info" ascii
        $path1 = "/supershell/monitor/status" ascii
        $path2 = "/supershell/monitor/clients" ascii
        $path3 = "/supershell/monitor/compiled" ascii
        $path4 = "/supershell/monitor/rssh" ascii
rule SuperShell_HTTP_Traffic {
        description = "Detects SuperShell C2 HTTP traffic patterns in PCAP/network captures"
        $uri1 = "/supershell/login/auth" ascii
        $uri2 = "/supershell/monitor/" ascii
        $uri3 = "/supershell/client" ascii
        $uri4 = "/supershell/session/" ascii
        $uri5 = "/supershell/setting/" ascii
        $header = "Content-Type: application/json" ascii nocase
        any of ($uri*) and $header
rule CrestSnake_WSH_Lure {
        description = "Detects WSH lure files from Crest Snake / Nutten Tunnel campaign"
        $wsh1 = "[ScriptFile]" ascii
        $wsh2 = "trycloudflare.com@SSL\\DavWWWRoot" ascii
        $wsh3 = "UseEngine=JScript" ascii
        $wsh4 = ".wsf" ascii
        filesize < 500 and $wsh1 and $wsh2 and ($wsh3 or $wsh4)
rule CrestSnake_WSF_Dropper {
        description = "Detects WSF dropper files copying BAT payloads from trycloudflare WebDAV"
        $wsf1 = "CopyAndExecuteBats" ascii
        $wsf2 = "trycloudflare.com@SSL\\DavWWWRoot" ascii wide
        $wsf3 = "WScript.Shell" ascii
        $wsf4 = "Scripting.FileSystemObject" ascii
        $wsf5 = "CopyFile" ascii
        $wsf6 = "%USERPROFILE%\\Contacts\\" ascii
        filesize < 5KB and $wsf2 and 3 of ($wsf*)
rule CrestSnake_BAT_Stager {
        description = "Detects BAT stager scripts from Crest Snake campaign"
        $bat1 = "Contacts\\MainRingtones" ascii nocase
        $bat2 = "Contacts\\docuts" ascii nocase
        $bat3 = "Contacts\\str" ascii nocase
        $bat4 = "highland-trend-src-distinct.trycloudflare.com" ascii
        $bat5 = "chubby-resident-airlines-converter.trycloudflare.com" ascii
        $bat6 = "python312x64" ascii nocase
        $bat7 = "python312x32" ascii nocase
        $bat8 = "attrib +h" ascii
        $bat9 = "\\Contacts\\rhn.vbs" ascii
        $bat10 = "DiscordDial.vbs" ascii
        filesize < 10KB and 3 of ($bat*)
rule CrestSnake_EarlyBird_DLL {
        description = "Detects the Early Bird APC injection DLL from Crest Snake campaign"
        hash = "3ea83adc47138478ed646170b88581af441f24feeee7f8472868286aadb132fd"
        imphash = "88063500446cf32cf6c9ede2df6ccec0"
        $exp1 = "get_payload" ascii
        $exp2 = "inject_early_bird" ascii
        $exp3 = "xor_decrypt" ascii
        $key = "vGTemXQ2PUmLBCzOAPieOYoLGTonlAQ4" ascii
        $path1 = "magde.dat" wide
        $path2 = "Microsoft\\DiagSvc" wide
        $path3 = "msv1_0.dll" wide
        $path4 = "CertificateCheck.bat" wide
        $bat = "@echo off" ascii
        $regsvr = "regsvr32 /s" ascii
        uint16(0) == 0x5A4D and filesize < 50KB and 
        (2 of ($exp*) or $key or 3 of ($path*))
rule CrestSnake_Persistence_BAT {
        description = "Detects startup persistence BAT with multi-Python execution pattern"
        $s1 = "Winic\\30.3.0rc50\\Python312x32" ascii nocase
        $s2 = "Contacts\\Str\\python312x64" ascii nocase
        $s3 = "LaunchAndClean" ascii
        $s4 = "DiscordDial.vbs" ascii
        $s5 = "nslookup.exe" ascii
        $s6 = "explorer.exe" ascii
        $s7 = "python.exe" ascii
        $s8 = "Terminate" ascii
        filesize < 10KB and 4 of ($s*)
rule CrestSnake_Kramer_Obfuscated_Python {
        description = "Detects Kramer-obfuscated Python 3.12 compiled bytecode payloads"
        $magic = { cb 0d 0d 0a }
        $class = "Kramer" ascii
        $method = "__decode__" ascii
        $bit = "_bit" ascii
        $magic at 0 and $class and ($method or $bit)
rule ClickFix_BookingCom_Lure {
        description = "Detects ClickFix fake CAPTCHA page impersonating Booking.com"
        $booking_logo = "booking.com_logo.svg" ascii wide nocase
        $booking_svg = "bookingcom-1.svg" ascii wide nocase
        $clickfix_text1 = "Checking if you are human" ascii wide
        $clickfix_text2 = "I'm not a robot" ascii wide
        $clickfix_text3 = "Press" ascii wide
        $clickfix_text4 = "Windows Key" ascii wide
        $ps_clipboard1 = "document.execCommand('copy')" ascii wide
        $ps_clipboard2 = "navigator.clipboard.writeText" ascii wide
        $ps_payload = "powershell" ascii wide nocase
        $devtool_block = "disable-devtool" ascii wide
        $verify_step = "Verify you are human" ascii wide
        $request_click = "/request/click/" ascii wide
        (($booking_logo or $booking_svg) and 2 of ($clickfix_text*) and 1 of ($ps_clipboard*)) or
        (3 of ($clickfix_text*) and $ps_payload and 1 of ($ps_clipboard*) and $devtool_block)
rule ClickFix_PowerShell_Stager {
        description = "Detects ClickFix PowerShell clipboard stager pattern"
        $pattern1 = "powershell -wind" ascii wide nocase
        $pattern2 = "sv o ir" ascii wide nocase
        $pattern3 = "(gv o).Value" ascii wide nocase
        $pattern4 = "Anti-BOT Check" ascii wide nocase
        $pattern5 = "-wi hid" ascii wide nocase
        $irm = "irm " ascii wide nocase
        filesize < 1KB and 2 of them
rule NetSupport_RAT_Dropper_PS1 {
        description = "Detects NetSupport RAT PowerShell dropper with base64-encoded file manifest"
        hash = "00e8f28233776a2ebe59cd547694b83012d5d9697a5f021a7b6e7e9aa9553922"
        $func = "function __b64" ascii
        $desktop = "RGVza3RvcA==" ascii
        $hidden = "SGlkZGVu" ascii
        $service = "c2VydmljZS5leGU=" ascii
        $client32 = "Y2xpZW50MzIuaW5p" ascii
        $htctl = "SFRDVEwzMi5ETEw=" ascii
        $nsm_lic = "TlNNLkxJQw==" ascii
        $runmru = "SEtDVTpcU29mdHdhcmVcTWljcm9zb2Z0" ascii
        $startup = "Start Menu\\Programs\\Startup" ascii wide nocase
        $manifest = "EncodedPayload" ascii
        $json = "ConvertFrom-Json" ascii
        filesize > 1MB and filesize < 20MB and
        $func and $manifest and 3 of ($desktop, $hidden, $service, $client32, $htctl, $nsm_lic, $runmru)
rule NetSupport_RAT_Config_Malicious {
        description = "Detects maliciously configured NetSupport Manager client32.ini (stealth mode)"
        $s1 = "silent=1" ascii
        $s2 = "SysTray=0" ascii
        $s3 = "SKMode=1" ascii
        $s4 = "ShowUIOnConnect=0" ascii
        $s5 = "DisableDisconnect=1" ascii
        $s6 = "DisableChatMenu=1" ascii
        $s7 = "GatewayAddress=" ascii
        $s8 = "SecondaryGateway=" ascii
        $s9 = "GSK=" ascii
        $s10 = "RoomSpec=" ascii
        filesize < 10KB and $s1 and $s2 and $s3 and $s4 and 3 of ($s5, $s6, $s7, $s8, $s9, $s10)
rule NetSupport_RAT_Campaign_GSK {
        description = "Detects specific NetSupport RAT campaign by Gateway Shared Key"
        $gsk = "GI<EAEEI:D?GDBHF=A?GAM" ascii
        $room = "RoomSpec=Eval" ascii
        $license = "NSM1234" ascii
 * YARA Rules — GELD-PAYPAL / MHost SMS Fraud Operation
 * Author: GHOST — Breakglass Intelligence
 * Date: 2026-04-03
 * TLP: WHITE
rule GeldPaypal_SMS_API_Panel {
        description = "Detects the Russian-language SMS API Proxy test panel HTML"
        campaign = "GELD-PAYPAL"
        $title = "SMS API Proxy - Test Panel" ascii wide
        $lang = "<html lang=\"ru\">" ascii
        $api_key_ru = {D0 A2 D1 80 D0 B5 D0 B1 D1 83 D0 B5 D1 82 D1 81 D1 8F 20 41 50 49} // "Требуется API" in UTF-8
        $endpoint1 = "/get-number/" ascii
        $endpoint2 = "/get-sms/" ascii
        $endpoint3 = "/api/providers/services" ascii
        $endpoint4 = "/api/providers/operators" ascii
        $service1 = "freenet" ascii
        $service2 = "gmx" ascii
        $service3 = "klein" ascii
        $title or ($lang and 2 of ($endpoint*)) or (3 of ($service*) and any of ($endpoint*))
rule GeldPaypal_SMS_API_Server_Response {
        description = "Detects SMS API Server v1.0.0 JSON response pattern"
        $api_name = "\"name\":\"SMS API Server\"" ascii
        $version = "\"version\":\"1.0.0\"" ascii
        $get_number = "\"getNumber\":\"GET /get-number/" ascii
        $get_sms = "\"getSms\":\"GET /get-sms/" ascii
        $finish = "\"finishActivation\":\"POST /finish/" ascii
        $cancel = "\"cancelActivation\":\"POST /cancel/" ascii
        ($api_name and $version) or 3 of ($get_number, $get_sms, $finish, $cancel)
rule GeldPaypal_Caddy_C2_Fingerprint {
        description = "Detects Golang/Caddy C2 HTTP response pattern with double Via header and CORS"
        $via_double = "Via: 1.1 Caddy\r\nVia: 1.1 Caddy" ascii
        $cors_origin = "Access-Control-Allow-Origin: *" ascii
        $cors_creds = "Access-Control-Allow-Credentials: true" ascii
        $request_id = "X-Request-Id:" ascii
        $health_ok = "ok" ascii
        $via_double and $cors_origin and $cors_creds and $request_id
rule GeldPaypal_Phishing_Domain_IOC {
        description = "Detects references to GELD-PAYPAL campaign phishing domains"
        $domain1 = "geld-paypal.com" ascii wide nocase
        $domain2 = "beveiligdbetaald.com" ascii wide nocase
        $ip1 = "45.151.106.88" ascii wide
        $ip2 = "95.85.236.1" ascii wide
rule Phishing_FattureWeb_Clone {
        description = "Detects FattureWeb phishing kit clone targeting Italian e-invoicing platform"
        campaign = "Operation REFIRE"
        $nonce = "RkFUVFVSRSBXRUI=" ascii
        $title = "FattureWeb- Sistemi" ascii
        $session_code = "904e7280ace5b3688dc6fd4d61a4f75b" ascii
        $dynatrace_app = "d95abcde924c0830" ascii
        $dynatrace_rid = "RID_2418" ascii
        $recaptcha_v2 = "6LflcFgpAAAAAFaLNYamOacvTibT4zqSaG7ZTe0c" ascii
        $recaptcha_v3 = "6LdXcFgpAAAAAFdF9RleQxfI5w_aVGf2PllZB7Qv" ascii
        $disable_console = "disableConsoleMessages" ascii
        $submit_ajax = "section=login&option=submitAjax" ascii
        $submit_pwd = "section=login&option=submitPasswordAjax" ascii
        $fattureweb_domain = "fattureweb-sistem" ascii
rule Phishing_Italian_Banking_Redirector {
        description = "Detects Italian banking phishing redirector pages with hidden tracking tags"
        $hidden_h1 = "<h1 style=\"display:none\">" ascii
        $redirect = "window.location.href=\"/" ascii
        $favicon = "<link rel=\"icon\" href=\"data:,\">" ascii
        $onload = "window.onload=function()" ascii
        filesize < 500 and 3 of them
rule Phishing_Italian_Banking_IP_Filter {
        description = "Detects IP-based access control page used by Italian phishing campaign"
        $ip_block = "Your IP address" ascii
        $must_allow = "must be allowed before access" ascii
        filesize < 200 and all of them
rule Phishing_WordPress_ResponsiveCountdown_Stager {
        description = "Detects WordPress compromise via responsive-countdown plugin used for phishing staging"
        $plugin_path = "wp-content/plugins/responsive-countdown/lib/ssl" ascii
        $fattureweb = "fattureweb" ascii nocase
rule Kimsuky_BlogHarvest_DDNS_Config {
        description = "Detects Kimsuky malware containing Blog Harvest campaign DDNS domains"
        reference = "https://intel.breakglass.tech/post/operation-blog-harvest"
        $ddns1 = "auth-umblog" ascii wide nocase
        $ddns2 = "dynv6.net" ascii wide nocase
        $ddns3 = "mydns.bz" ascii wide nocase
        $ddns4 = "mydns.vc" ascii wide nocase
        $ddns5 = "dns.army" ascii wide nocase
        $ddns6 = "ntsaccessmember" ascii wide nocase
        $ddns7 = "nhsdomainspf" ascii wide nocase
        $ddns8 = "memberblogvisit" ascii wide nocase
        $ddns9 = "invoicesetupsvc" ascii wide nocase
        $ddns10 = "ipsdelivercheck" ascii wide nocase
        $ddns11 = "ntplnk5s" ascii wide nocase
        $ddns12 = "memberlogcheck" ascii wide nocase
        $ddns13 = "npsdkimrecord" ascii wide nocase
        $ddns14 = "nhbasetarget" ascii wide nocase
        $ddns15 = "controlbloginfo" ascii wide nocase
        $ddns16 = "ublogblock" ascii wide nocase
        $ddns17 = "account-kakao" ascii wide nocase
        $ddns18 = "reverifyusrprofile" ascii wide nocase
        $ddns19 = "nhireferal" ascii wide nocase
        $ddns20 = "ntverifyrecord" ascii wide nocase
        $ip1 = "158.247.219.150" ascii wide
        $ip2 = "158.247.197.123" ascii wide
        $ip3 = "141.164.61.168" ascii wide
        $ip4 = "152.32.138.158" ascii wide
        $domain1 = "navercoorp.com" ascii wide nocase
        $domain2 = "nld-naver.com" ascii wide nocase
        $domain3 = "nts-report.info" ascii wide nocase
        $domain4 = "nhis-web.cv" ascii wide nocase
        $domain5 = "baroitda.co.kr" ascii wide nocase
        $domain6 = "wireguard-vpn.com" ascii wide nocase
        2 of ($ddns*) or any of ($ip*) or any of ($domain*)
rule Kimsuky_BlogHarvest_URL_Pattern {
        description = "Detects Kimsuky Blog Harvest phishing URL patterns in scripts/configs"
        $pattern1 = /auth-umblog\d{1,3}s\.dynv6\.net/ ascii wide
        $pattern2 = /www\.auth-umblog\d{1,3}s\.dynv6\.net/ ascii wide
        $pattern3 = /[a-z]{5,12}\.auth-umblog\d{1,3}s\.dynv6\.net/ ascii wide
        $pattern4 = /(edoc|info|invoice|doc|docinf|userinfo|verify)\.[a-z]+\.(mydns\.bz|mydns\.vc|dns\.army)/ ascii wide
rule Kimsuky_Korean_Phishing_Indicators {
        description = "Generic detection for Kimsuky Korean-targeted phishing indicators"
        $nts1 = "nts.go.kr" ascii wide nocase
        $nts2 = "hometax" ascii wide nocase
        $naver1 = "nid.naver.com" ascii wide nocase
        $naver2 = "naver" ascii wide nocase
        $kakao1 = "accounts.kakao.com" ascii wide nocase
        $nh1 = "nhis" ascii wide nocase
        $nps1 = "nps.or.kr" ascii wide nocase
        $ddns_sus1 = "mydns.bz" ascii wide
        $ddns_sus2 = "dynv6.net" ascii wide
        $ddns_sus3 = "dns.army" ascii wide
        $ddns_sus4 = "kro.kr" ascii wide
        any of ($nts*, $naver1, $kakao1, $nh1, $nps1) and any of ($ddns_sus*)
rule HYFLOCK_RaaS_Panel_HTML {
        description = "Detects HYFLOCK RaaS panel HTML content"
        $title1 = "HYFLOCK" ascii wide
        $title2 = "RAAS PANEL" ascii wide
        $login_type = "login_type" ascii
        $attacker = "value=\"attacker\"" ascii
        $customer = "value=\"customer\"" ascii
        $target_id = "target_id" ascii
        $enter_room = "ENTER ROOM" ascii wide
        $copyright = "2025 HYFLOCK" ascii wide
        $ddos = "ddos-verify" ascii
rule HYFLOCK_RaaS_CSS_Fingerprint {
        description = "Detects HYFLOCK RaaS panel CSS with Chinese developer comments"
        $cn1 = { E5 AE A2 E6 88 B7 E6 8E A5 E5 8F 97 E6 8A A5 E4 BB B7 E6 A0 B7 E5 BC 8F }
        $cn2 = { E8 81 8A E5 A4 A9 E7 95 8C E9 9D A2 E4 BC 98 E5 8C 96 }
        $cn3 = { E6 94 AF E4 BB 98 E7 8A B6 E6 80 81 }
        $cn4 = { E7 94 9F E6 88 90 E5 99 A8 E8 A1 A8 E5 8D 95 }
        $css1 = ".leak-zoominfo" ascii
        $css2 = ".generator-glass" ascii
        $css3 = ".chat-message-glass" ascii
        $css4 = ".payment-glass" ascii
        $css5 = ".status-pending_customer_acceptance" ascii
        $css6 = ".status-customer_rejected" ascii
        2 of ($cn*) or 4 of ($css*)
rule CloudflareTunnel_WSF_Dropper {
        description = "Detects WSF dropper scripts used in Cloudflare tunnel malware campaigns (Operations Klein Changes / Crest Snake / Nutten Tunnel)"
        $wsf_tag = "<job id=" ascii
        $jscript = "language=\"JScript\"" ascii
        $activex_shell = "ActiveXObject(\"WScript.Shell\")" ascii
        $activex_fso = "ActiveXObject(\"Scripting.FileSystemObject\")" ascii
        $davwwwroot = "DavWWWRoot" ascii
        $ssl_webdav = "@SSL\\DavWWWRoot\\" ascii
        $regsvr32 = "regsvr32 /s" ascii
        $copyfile = "CopyFile(webdavPath" ascii
        $contacts = "\\Contacts\\" ascii
        filesize < 5KB and
        $wsf_tag and $jscript and
        ($trycloudflare or $davwwwroot) and
        any of ($activex_shell, $activex_fso, $regsvr32, $copyfile)
rule CloudflareTunnel_BAT_Stager {
        description = "Detects BAT stager scripts used in Cloudflare tunnel multi-stage malware campaigns"
        $bat_header = "cls" ascii
        $echo_off = "@echo off" ascii nocase
        $delayed = "EnableDelayedExpansion" ascii nocase
        $vbs_relaunch = "WScript.Shell" ascii
        $hidden_check = "neq \"hidden\"" ascii
        $contacts_dir = "\\Contacts\\" ascii
        $highland = "highland-trend-src-distinct.trycloudflare.com" ascii
        $chubby = "chubby-resident-airlines-converter.trycloudflare.com" ascii
        $mainringtones = "MainRingtones" ascii
        $python312 = "python312x64" ascii
        $attrib_hide = "attrib +h" ascii
        $del_bats = "del /q \"%CONTACTSFOLDER%\\*.bat\"" ascii
        $wmi_kill = "Win32_Process" ascii
        $curl_download = "curl -f -L -o" ascii
        $echo_off and
        3 of ($vbs_relaunch, $hidden_check, $contacts_dir, $mainringtones, $python312, $attrib_hide, $del_bats, $wmi_kill, $curl_download) and
        any of ($highland, $chubby)
rule EarlyBird_XOR_Loader_DLL {
        description = "Detects Early Bird APC injection DLL with XOR decryption (jopfgl.dll pattern)"
        $export1 = "get_payload" ascii
        $export2 = "inject_early_bird" ascii
        $export3 = "xor_decrypt" ascii
        $export4 = "DllRegisterServer" ascii
        $xor_key = "vGTemXQ2PUmLBCzOAPieOYoLGTonlAQ4" ascii
        $gcc = "GCC: (x86_64-posix-seh" ascii
        $mingw = "Mingw-w64 runtime" ascii
        $regsvr_cmd = "regsvr32 /s" ascii
        $mz_check = ":MZ" ascii
        2 of ($export1, $export2, $export3) and
        any of ($xor_key, $gcc, $mingw)
rule CloudflareTunnel_Persistence_BAT {
        description = "Detects persistence scripts that execute Python RAT payloads from multiple hidden directories"
        $winic = "\\Winic\\" ascii
        $python312x32 = "Python312x32" ascii
        $python312x64 = "python312x64" ascii
        $discorddial = "DiscordDial.vbs" ascii
        $contacts_str = "\\Contacts\\Str\\" ascii
        $kill_explorer = "explorer.exe" ascii
        $kill_python = "python.exe" ascii
        $wmi = "winmgmts" ascii
        $terminate = "Terminate" ascii
        $startup = "Start Menu\\Programs\\Startup" ascii
        3 of ($winic, $python312x32, $python312x64, $discorddial, $contacts_str, $mainringtones) and
        any of ($kill_explorer, $wmi, $terminate) and
        $startup
rule TwizAdmin_Stealer_CryptoGuard {
        description = "TwizAdmin CryptoGuard clipper/stealer module"
        hash = "f7ddba605e3d04e06d2f7b0fc4a38027ae58ca65a69d800dd2f43c8e94ca8396"
        $api_secret = "26i$MyYe@r" ascii
        $c2_domain = "fanonlyatn" ascii
        $class3 = "BackgroundInstaller" ascii
        $func3 = "get_matching_address_from_api" ascii
        $func4 = "check_and_execute_tasks" ascii
        $persist1 = "com.cryptoprice.guard" ascii
        $persist2 = "com.sys32.data" ascii
        $wallet_trx = "TDtxY9ZHNffj14Ci9qhBjkpR2AAhCaHuXs" ascii
        $build_id = "BUILD_ID = 'v1.2" ascii
        $hidden_dir = ".sys32data" ascii
rule TwizAdmin_SeedFinder {
        description = "TwizAdmin BIP-39 seed phrase scanner module (finder.py)"
        hash = "9d9783f57fd543043e0792d125831883259c823a5eaa69211e5254db4db4eaec"
        $action1 = "seed_detected" ascii
        $action2 = "multiple_seeds_detected" ascii
        $action3 = "scan_started" ascii
        $config1 = "v2.2_ULTRA_STRICT" ascii
        $config2 = "API_CONFIG_SECRET" ascii
        $c2 = "fanonlyatn" ascii
rule TwizAdmin_Crypter_crpx0 {
        description = "TwizAdmin ransomware module (crpx0 extension)"
        $ext = ".crpx0" ascii
        $note = "HOW TO RECOVER" ascii
        $ru_c2_1 = "caribb.ru" ascii
        $ru_c2_2 = "mekhovaya-shuba.ru" ascii
        $ru_c2_3 = "beboss34.ru" ascii
        $func3 = "stage3_decrypt" ascii
        $fernet = "Fernet" ascii
        $ru_note = {D0 9F D0 BE D1 81 D0 BB D0 B5 D0 B4 D0 BD D0 B5 D0 B5} // "Последнее" in UTF-8
rule TwizAdmin_MacOS_Loader {
        description = "TwizAdmin macOS bash loader scripts"
        $url = "fanonlyatn.xyz/files/" ascii
        $python_dl = "python-build-standalone" ascii
        $fedex_lure = "FedEx Secure Access" ascii
        $of_lure = "OnlyFans Secure Archive" ascii
        $password = "pass2021#" ascii
        $bundle1 = "com.fedex.delivery.details" ascii
        $bundle2 = "com.onlyfans.secure.access" ascii
rule TwizAdmin_Call2_Orchestrator {
        description = "TwizAdmin call2.py orchestrator/dropper"
        $dir = "_HIDDEN_DIR_NAME" ascii
        $file = "_SYSDATA_FILENAME" ascii
        $url1 = "fanonlyatn.xyz/builds/last.zip" ascii
        $url2 = "fanonlyatn.xyz/builds/scan/finderx.zip" ascii
        $patch1 = "AGENT_ID = 'default'" ascii
        $patch2 = "Robustly disable pyautogui" ascii
        $persist = "com.sys32.data.plist" ascii
        $debug = "call2_debug.txt" ascii
    YARA Rules: XWorm V6.0 "backupallfresh2030" Campaign
    Reference: https://intel.breakglass.tech
rule XWorm_V6_Generic {
        description = "Detects XWorm V6.0 RAT (@XCoderTools) based on User String patterns"
        hash = "8d82e3757e9db0fc247350ab3140a21badcf8d6c60dfe79200d7d1e2a93dba14"
        $xworm_banner = { 2600 2000 5B00 5800 5700 6F00 7200 6D00 2000 5600 3600 2E00 3000 } // "& [XWorm V6.0" in UTF-16LE
        $xworm_tag = "XWorm V6.0" ascii wide
        $xcoder = "@XCoderTools" ascii wide
        $cmd_pong = "pong" ascii wide
        $cmd_ddos_start = "StartDDos" ascii wide
        $cmd_ddos_stop = "StopDDos" ascii wide
        $cmd_report = "StartReport" ascii wide
        $cmd_xchat = "Xchat" ascii wide
        $cmd_hostsmsg = "HostsMSG" ascii wide
        $cmd_plugin = "sendPlugin" ascii wide
        $cmd_recovery = "RunRecovery" ascii wide
        $cmd_uac = "UACFunc" ascii wide
        $cmd_inject = "injRun" ascii wide
        $cmd_options = "RunOptions" ascii wide
        $vb_host = "$VB$Local_Host" ascii
        $vb_port = "$VB$Local_Port" ascii
        $sandbox_check = "http://ip-api.com/line/?fields=hosting" ascii wide
            ($xworm_banner or $xworm_tag or $xcoder) and
            3 of ($cmd_*) and
            ($vb_host or $vb_port)
        ) or
            $xworm_tag and $sandbox_check
rule XWorm_V6_dddd_Variant {
        description = "Detects specific dddd.exe XWorm V6.0 variant from backupallfresh2030 campaign"
        $config1 = "BB9PeNklhXbQAQf3YIPbFxtjrnrc8vQUhQ6vCReQ7ZWk16caTSWXvPP4Dw" ascii wide
        $config2 = "wqyKQFzVDd4esEWlwKMvJSGN1oGN0CYKuPbxOkJ5WlCZLlIpsVRpTc8ueCFRzUsehm4dBXGsQXyXkXuLNvgZVFsvPS" ascii wide
        $config3 = "Qel9RQu5KOgMqhGpX2ZLcRpzYo8MTksL" ascii wide
        $imphash = "f34d5f2d4577ed6d9ceec516c1f5a744"
        2 of ($config*)
rule XWorm_JS_Dropper_IaYvjqgOMp {
        description = "Detects XWorm JS dropper using IaYvjqgOMp junk string interleaving"
        hash = "0794add65a271388acc6ab87a0dc2fe47373b40921f22dec12c02f74fbe6b154"
        $junk = "IaYvjqgOMp" ascii
        $wscript = /WScr.{0,10}pt\..{0,5}Shell/ ascii
        $activex = /ActiveXObject.*Scripting.*Dictionary/ ascii
        $ps_encoded = "EncodedCommand" ascii nocase
        #junk > 50 and
        ($wscript or $activex) and
        $ps_encoded
rule XWorm_BAT_Dropper_Turkish {
        description = "Detects Turkish-origin XWorm BAT dropper with Defender evasion"
        hash = "864eedb88690d3a8479f9deb175e8cd8762b73459c5944684cc05055d14fde27"
        $turkish = "izni kontrol" ascii wide  // Turkish admin check
        $defender_excl = "Add-MpPreference -ExclusionPath" ascii nocase
        $defender_ext = "Add-MpPreference -ExclusionExtension" ascii nocase
        $defender_proc = "Add-MpPreference -ExclusionProcess" ascii nocase
        $github_raw = "raw.githubusercontent.com" ascii nocase
        $microsys = "Microsys.exe" ascii nocase
        $startup = "Start Menu\\Programs\\Startup" ascii nocase
        $turkish and
        2 of ($defender_*) and
        ($github_raw or $microsys or $startup)
rule XWorm_Trojanized_Python_Loader {
        description = "Detects obfuscated Python loader used in XWorm campaign (Protected.py pattern)"
        $decode_func = "_spIvxmOlxyrRncug6XRQAZJvHjaRUHpp" ascii
        $builtin_class = "_cCLe6QapwlMP8dRyovJTvEJF64KqGx5G" ascii
        $xor_rot13 = "rot13" ascii
        $aes_key_marker = "aes_key" ascii
        $shellcode_msg = "Decrypting shellcode" ascii
        $startup_vbs = "SyncAppvPublishingServer.vbs" ascii
        $rtk_persist = "RtkAudUService" ascii
        $python_path = "python312x64" ascii
            ($decode_func and $builtin_class) or
            ($aes_key_marker and $shellcode_msg) or
            ($startup_vbs and $rtk_persist and $python_path)
rule XWorm_Campaign_Filemail_Delivery {
        description = "Detects PowerShell downloading trojanized Python from Filemail (backupallfresh campaign)"
        $filemail = "filemail.com" ascii nocase
        $python_zip = "python312x64.zip" ascii nocase
        $templates = "AppData\\Roaming\\Templates" ascii nocase
        $protected = "Protected.py" ascii nocase
        $pythonw = "pythonw.exe" ascii nocase
        filesize < 50MB and
        $filemail and
        ($python_zip or $templates) and
        ($protected or $pythonw)
rule XWorm_GitHub_Staging_flexhere687 {
        description = "Detects references to flexhere687-art GitHub malware staging repos"
        $gh1 = "flexhere687-art" ascii nocase
        $gh2 = "flexhere687" ascii nocase
        $repo1 = "xvxc-" ascii
        $repo2 = "vxcxc-xcv" ascii
        ($gh1 or $gh2) and ($repo1 or $repo2)
rule InterviewBait_Phishing_Kit_JS {
        date = "2026-04-05"
        description = "Detects the InterviewBait AiTM phishing kit JavaScript bundle"
        hash = "main.fdf3901b.js"
        $api1 = "/api/new-user" ascii
        $api2 = "/api/booking" ascii
        $api3 = "/api/login" ascii
        $api4 = "/api/email" ascii
        $api5 = "/api/twofa" ascii
        $api6 = "/api/sms" ascii
        $api7 = "/api/tap" ascii
        $api8 = "/check_response" ascii
        $api9 = "/api/resend/app" ascii
        $api10 = "/api/get-channel-id" ascii
        $render = "onrender.com" ascii
        $google_fake = "accounts.google.com/signin/v3/" ascii
        $persona = "Tricia Guyer" ascii
        $ipwho = "ipwho.is" ascii
        $booking_telegram = "booking" ascii
        $ga_id = "G-123NZLZV56" ascii
        $class1 = "google-signin-heading" ascii
        $class2 = "google-login-form" ascii
        $class3 = "calendly-back" ascii
        $meeting = "30 Minute Meeting" ascii
        3 of ($api*) or
        ($render and $google_fake) or
        ($persona and $meeting) or
        $ga_id or
        ($class1 and $class2 and $class3)
rule InterviewBait_Phishing_Kit_HTML {
        description = "Detects the InterviewBait phishing kit HTML landing page"
        $title1 = "Book a Call" ascii
        $ga = "G-123NZLZV56" ascii
        $js = "main.fdf3901b.js" ascii
        $css = "main.6de1a5d0.css" ascii
        $aem = "adobeaemcloud.com" ascii
        $manifest = "manifest.json" ascii
        $ga or
        ($js and $css) or
        ($title1 and $aem and $manifest)
rule InterviewBait_Backend_Response {
        description = "Detects InterviewBait C2 backend API responses"
        $resp1 = "\"redirect\":" ascii
        $resp2 = "\"authType\":" ascii
        $resp3 = "\"verification_number\":" ascii
        $resp4 = "\"session_id\":" ascii
        $openapi = "\"hrguxhellito281\"" ascii
        $endpoint = "Send booking data to Telegram" ascii
        ($resp1 and $resp2 and $resp3) or
        $openapi or
        $endpoint
rule CVE_2025_8088_ADS_Exploit_RAR {
        description = "Detects RAR archives exploiting CVE-2025-8088 via NTFS ADS path traversal to Startup folder"
        hash = "07f2d8f3a9c9430d91620d6a8b83c20dc9d020f00b7066b3ff9bd0fec20b7c2d"
        $rar5_sig = { 52 61 72 21 1A 07 01 00 }
        $ads_path1 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Updater.exe" ascii
        $ads_path2 = "..\\AppData\\Roaming\\Microsoft" ascii
        $ads_path3 = "../AppData/Roaming/Microsoft" ascii
        $pad_name = "_wr_storage_pad_" ascii
        $rar5_sig at 0 and $pad_name and ($ads_path1 or $ads_path2 or $ads_path3)
rule MaQ_Telegram_RAT_Config_Encryption {
        description = "Detects MaQ Telegram RAT by config encryption artifacts"
        hash = "59100fba79307120816c9733e38d85a2c9b769905f1a8177863a5b97255ca46e"
        $key = "MaQ_S3cur3_K3y_2024_Pr0t3ct3d!" ascii wide
        $salt = "maq_salt_v1" ascii wide
        $func1 = "_maq_sk_bytes" ascii
        $func2 = "_maq_sec_decode" ascii
rule MaQ_Telegram_RAT_Behavioral {
        description = "Detects MaQ Telegram RAT by behavioral strings"
        $s1 = "ekran_goruntusu" ascii wide
        $s2 = "WindowsServices" ascii wide
        $s3 = "lock_api.php" ascii wide
        $s4 = "register_pc" ascii wide
        $s5 = "list_pcs" ascii wide
        $s6 = "set_preferred_master" ascii wide
        $s7 = "Fodhelper UAC Bypass" ascii wide
        $s8 = "robertabot" ascii wide
        $s9 = "leader_election" ascii wide
        $tg1 = "ADMIN_CHAT_ID" ascii
        $tg2 = "NOTIFY_CHANNEL_ID" ascii
        $tg3 = "BOT_PASSWORD" ascii
        3 of ($s*) or (2 of ($tg*) and 1 of ($s*))
rule MaQ_Telegram_RAT_Updater {
        description = "Detects the .NET downloader component of MaQ Telegram RAT"
        hash = "f130fafb1d81adb66184751b96b8673fbbff7118990753f97c3a1ef33ee0fd84"
        $mz = { 4D 5A }
        $dotnet = "_CorExeMain" ascii
        $url = "/data/WindowsServices.exe" ascii wide
        $mz at 0 and $dotnet and $url and filesize < 20KB
rule Kimsuky_IPFS_Credential_Harvester {
        description = "Kimsuky IPFS-hosted obfuscated JavaScript credential harvester used across webmail, Zoom, and Naver phishing campaigns"
        hash = "2ed21819cb409f2b4189b4d1625e42eff6a09bb359912443395626ba95902f19"
        $ipfs_cid = "bafkreibo2imbts2at4vudcnu2frf4qxp62qjxm2zsesegokwe25jlebpde" ascii wide
        $ipfs_gateway = "ipfs.w3s.link" ascii wide
        $obf_func1 = "_0x5032" ascii
        $obf_func2 = "_0x41f4" ascii
        $obf_func3 = "_0x3808d1" ascii
        $blob_landing = "Blob landi" ascii
        $error_msg = "error-message" ascii
        any of ($ipfs_cid, $ipfs_gateway) or
        (3 of ($obf_func1, $obf_func2, $obf_func3, $blob_landing, $error_msg))
rule Kimsuky_Webmail_Phishing_Page {
        description = "Kimsuky Roundcube/Webmail phishing page with IPFS payload and anti-forensic keyboard blocking"
        $title1 = "Roundcube Webmail :: Welcome to Roundcube Webmail" ascii wide
        $title2 = "Webmail Login" ascii wide
        $title3 = "Webmail Oauth" ascii wide
        $ipfs = "ipfs.w3s.link" ascii wide
        $jquery1 = "jquery/2.2.4/jquery.min.js" ascii
        $jquery2 = "jquery-3.1.1.min.js" ascii
        $jquery3 = "jquery-3.3.1.js" ascii
        $anti1 = "event.preventDefault()" ascii
        $anti2 = "contextmenu" ascii
        $anti3 = "keyCode === 67" ascii
        $anti4 = "keyCode === 85" ascii
        any of ($title*) and
        $ipfs and
        2 of ($jquery*) and
        2 of ($anti*)
rule Kimsuky_Zoom_Phishing_Kit {
        description = "Kimsuky Zoom meeting phishing kit with Telegram exfiltration and forced multi-attempt credential harvesting"
        $zoom_title = "Zoom-Call-Group-Meeting" ascii wide
        $book = "Book Your Zoom Meeting Here" ascii wide
        $join = "Join Online Meeting" ascii wide
        $telegram_api = "api.telegram.org/bot" ascii wide
        $telegram_send = "sendMessage?chat_id=" ascii wide
        $ipify = "api.ipify.org" ascii wide
        $anti_test1 = {22 74 65 73 74 69 6E 67 22}
        $anti_test2 = {22 31 32 33 34 35 36 22}
        $anti_test3 = {22 70 61 73 73 77 6F 72 64 22}
        $anti_test4 = {22 71 77 65 72 74 79 22}
        $redirect_zoom = "us05web.zoom.us" ascii
        $reg_count = "reg_count" ascii
        ($zoom_title or $book or $join) and
        ($telegram_api or $telegram_send) and
        2 of ($anti_test*)
rule Kimsuky_Naver_Phishing {
        description = "Kimsuky Naver login phishing page targeting Korean users"
        $naver_favicon = "nid.naver.com/login/image/favicon.ico" ascii wide
        $jquery_triple = "jquery-3.3.1.js" ascii
        $anti_ctx = "contextmenu" ascii
        $naver_favicon and
        $anti_ctx
rule Kimsuky_FingerprintJS_Tracker {
        description = "Kimsuky phishing page with FingerprintJS visitor tracking and UUID session correlation"
        $fp_load = "FingerprintJS.load" ascii
        $fp_get = "fp.get()" ascii
        $fp_visitor = "result.visitorId" ascii
        $redirect = "redirect_link" ascii
        $tr_uuid = "tr_uuid" ascii
        $bg_color = "background:#101c36" ascii
rule Kimsuky_Linkgrid_Asset {
        description = "Assets loaded from linkgrid.ink phishing resource repository associated with Kimsuky operations"
        $linkgrid1 = "linkgrid.ink/rcubby" ascii wide
        $linkgrid2 = "linkgrid.ink/myjs" ascii wide
        $linkgrid3 = "linkgrid.ink/bab" ascii wide
        $linkgrid4 = "linkgrid.ink/ff" ascii wide
        $linkgrid5 = "linkgrid.ink" ascii wide
rule CVE_2026_21509_ShellExplorer2_OLE {
        description = "CVE-2026-21509 exploit via Shell.Explorer.2 OLE embedding in DOC files"
        hash = "81ecf0bbd62ef8602803b02d767cf2915875da82d156de57589733b58b36ad63"
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $shell_explorer2_clsid = { C3 2A B2 EA 30 C1 11 CF A7 EB 00 00 C0 5B AE 0B }
        $shell_explorer1_clsid = { 61 F9 56 88 0A 34 D0 11 A9 6B 00 C0 4F D7 05 A2 }
        $application_ext = ".application" ascii wide
        $b_cdn = "b-cdn.net" ascii wide
        $ole_magic at 0 and ($shell_explorer2_clsid or $shell_explorer1_clsid) and any of ($wps_uuid, $application_ext, $b_cdn)
rule CVE_2026_21509_BunnyCDN_Payload {
        description = "CVE-2026-21509 exploit documents using BunnyCDN for payload delivery"
        $url1 = "pdfviewer" ascii wide nocase
        $url2 = "b-cdn.net" ascii wide nocase
        $url3 = ".application" ascii wide nocase
        $clickonce = "Microsoft" ascii wide
        $pdf = "Pdf" ascii wide
        $ole_magic at 0 and $url2 and ($url1 or ($url3 and $clickonce and $pdf))
rule CVE_2026_21509_WPS_ExploitBuilder {
        description = "CVE-2026-21509 exploit builder fingerprint - shared WPS UUID across all known samples"
        $shell_explorer = { C3 2A B2 EA 30 C1 11 CF }
        $shell_explorer_alt = { 61 F9 56 88 0A 34 D0 11 }
        $objectpool = "ObjectPool" wide
        $ole_magic at 0 and $wps_uuid and ($shell_explorer or $shell_explorer_alt) and $objectpool
rule CVE_2026_21509_NasDoc_Specific {
        description = "Specific detection for nas.doc targeting NASTP Pakistan"
        $nastp = "NASTP" ascii wide
        $acppl = "ACPPL" ascii wide
        $aviation = "Aviation City Pakistan" ascii wide
        $pdfviewer = "pdfviewer2024" ascii wide
        $shell_clsid = { C3 2A B2 EA 30 C1 11 CF }
        $ole_magic at 0 and $shell_clsid and any of ($nastp, $acppl, $aviation, $pdfviewer)
rule SideWinder_Zimbra_PhishKit_CSS {
        description = "SideWinder APT Zimbra credential harvesting phishing kit - CSS fingerprint"
        hash = "07c63a73d5f4d11f41dfe9afd9bd3a3f99a0eca4a62439cf8f03eb0964137b78"
        investigation = "BGI-2026-041"
        $css_hash = "07c63a73d5f4d11f41dfe9afd9bd3a3f99a0eca4a62439cf8f03eb0964137b78"
        $css_hash
rule SideWinder_Zimbra_PhishKit_HTML {
        description = "SideWinder APT Zimbra credential harvesting phishing kit - HTML content detection"
        $param1 = "gfjdliotrgojnghgherbegrehureert0e0ee" ascii wide
        $param2 = "bfjkdghurehgjufhdkhgruiegbvousdhfowehr" ascii wide
        $param3 = "hfdgdhguirehfdhgfdrereoh" ascii wide
        $csrf = "ec529cbe-89f5-4964-b46f-b3dc29789899" ascii wide
        $title = "Zimbra Web Client Sign In" ascii wide
        $err1 = "Your Session Expired Enter Password to Sign in again" ascii wide
        $err2 = "Wrong password re-enter your password to sign in again" ascii wide
        $alt = "HIT logo" ascii wide
        $atob = "atob(value)" ascii wide
        $action1 = "action=\"/submit\"" ascii wide
        $action2 = "action=\"/try\"" ascii wide
        $param1 or $param3 or
        ($csrf and $title) or
        ($err1 and $atob) or
        ($err2 and $action2) or
        (3 of ($param1, $param2, $param3, $csrf, $alt, $atob))
rule SideWinder_Zimbra_PhishKit_LoadPage {
        description = "SideWinder APT Zimbra phishing kit intermediate loading page"
        $param_extract = "getQueryParameter('bfjkdghurehgjufhdkhgruiegbvousdhfowehr')" ascii wide
        $redirect = "login.html?gfjdliotrgojnghgherbegrehureert0e0ee=" ascii wide
        $loader_class = "class=\"loader\"" ascii wide
        $zimbra_title = "<title>Zimbra Web Client Sign In</title>" ascii wide
        ($param_extract or $redirect) and ($loader_class or $zimbra_title)
rule SideWinder_Zimbra_PhishKit_RootPage {
        description = "SideWinder APT Zimbra phishing kit root/landing page with PDF lure"
        $obj_pdf = "<object style=\"height:950px; width:1920px;\" data=\"./" ascii wide
        $redirect_load = "load.html?bfjkdghurehgjufhdkhgruiegbvousdhfowehr=" ascii wide
        $zimbra = "Zimbra Web Client Sign In" ascii wide
        $error_redirect = "error.html" ascii wide
        $redirect_load or
        ($obj_pdf and $zimbra) or
        ($obj_pdf and $error_redirect and $zimbra)
rule KISS_Loader_Early_Bird {
        description = "Detects KISS Loader - Early Bird APC Injection Python script used in Cloudflare tunnel campaigns"
        reference = "Operation Charger Van / Crest Snake / Klein Changes"
        $s5 = "CREATE_SUSPENDED" ascii
        $s6 = "xor_decrypt" ascii
        $s7 = "load_key" ascii
        $s8 = "VirtualAllocEx" ascii
        $s9 = "WriteProcessMemory" ascii
        filesize < 50KB and 5 of ($s*)
rule PurePythonObfuscator_KeyFile {
        description = "Detects PurePythonObfuscator XOR key files used in Cloudflare tunnel campaigns"
        hash = "ff5a9c8bad4d0afa5fba68a08cf91dbda0619c06a143dcd0aeb5c2c5dccd0274"
        $gen = "PurePythonObfuscator" ascii
        $key1 = "xor_key" ascii
        $key2 = "entropy_source" ascii
        $key3 = "secrets+urandom+time+pid" ascii
        $key4 = "random_seed" ascii
        $meta = "\"metadata\"" ascii
        $int = "\"integrity\"" ascii
        filesize < 5KB and $gen and 3 of ($key*, $meta, $int)
rule WsgiDAV_Tunnel_Dropper_WSH {
        description = "Detects WSH/JS dropper chain used in WsgiDAV Cloudflare tunnel campaigns"
        reference = "Operation Charger Van / Crest Snake / Nutten Tunnel"
        $wsh1 = "trycloudflare.com@SSL" ascii nocase
        $wsh2 = "DavWWWRoot" ascii nocase
        $js1 = "WScript.Shell" ascii
        $js2 = "Scripting.FileSystemObject" ascii
        $js3 = "CopyFile" ascii
        $bat1 = "trycloudflare.com/" ascii nocase
        filesize < 10KB and (2 of ($wsh*) or (1 of ($js*) and $bat1) or (all of ($js*)))
rule WsgiDAV_Tunnel_BatchDownloader {
        description = "Detects batch file downloaders from WsgiDAV Cloudflare tunnel campaigns"
        hash = "c37ccf440732aa346ea7541b80a3799bff4437e052023bacde50cef1c89801c2"
        reference = "Operation Charger Van"
        $url = "trycloudflare.com/" ascii nocase
        $curl = "curl -s -o" ascii nocase
        $py1 = "python.exe" ascii nocase
        $py2 = "so.py" ascii
        $py3 = "python-3.10.0-embed" ascii
        $zip = "Expand-Archive" ascii
        $bat = "WindowStyle Hidden" ascii
        $startup = "Programs\\Startup" ascii
        filesize < 10KB and $url and 3 of ($curl, $py1, $py2, $py3, $zip, $bat, $startup)
rule Donut_XOR_Encrypted_Payload {
        description = "Detects XOR-encrypted payloads with Donut shellcode characteristics used in tunnel campaigns"
        $bin_marker = { E8 [4] 88 BB 00 00 }
        filesize > 50KB and filesize < 500KB and $bin_marker at 0
rule TEAM24_Naver_Phishing_Page {
        description = "Detects TEAM24 Naver credential phishing page with base64-encoded exfil URL to arnptec.com"
        hash = "b7de02112b75c3a4484fd6d2e3859186a529bf5809397997fc41a5e555fe5163"
        $b64_exfil = "aHR0cHM6Ly9hcm5wdGVjLmNvbS90ZWFtMjQv" ascii
        $atob_call = "atob(" ascii
        $naver_meta = "content=\"\\xeb\\x84\\xa4\\xec\\x9d\\xb4\\xeb\\xb2\\x84\"" ascii
        $naver_title = "Naver Sign in" ascii nocase
        $form_id = "frmNIDLogin" ascii
        $double_tap = "count>=2" ascii
        $error_msg = "The username or password you entered is incorrect" ascii
        $jquery_submit = "$('form').submit(function" ascii
        $nid_css = "nid.naver.com/login/css" ascii
        $arnptec = "arnptec.com" ascii
            ($b64_exfil and $atob_call) or
            ($arnptec and $form_id) or
            ($naver_title and $double_tap and $jquery_submit) or
            (4 of ($naver_meta, $form_id, $double_tap, $error_msg, $nid_css, $jquery_submit))
rule TEAM24_Credential_Exfil_Pattern {
        description = "Detects phishing pages using base64-encoded arnptec.com exfiltration pattern"
        $arnptec_b64_team24 = "YXJucHRlYy5jb20vdGVhbTI0" ascii
        $arnptec_b64_fresh = "YXJucHRlYy5jb20vZnJlc2g" ascii
        $arnptec_plain = "arnptec.com/team24/" ascii
        $arnptec_fresh = "arnptec.com/fresh/" ascii
        $exfil_patterns = /arnptec\.com\/team24\/(nvvvr|daum|cafe24|ecount|general|wetransfer|whois|wrkkkkks|hwrrks)\// ascii
rule Vercel_Korean_Phishing_Generic {
        description = "Generic detection for Korean platform phishing pages hosted on Vercel with AJAX credential exfiltration"
        $vercel_indicator = "x-vercel-" ascii nocase
        $jquery_ajax = "$.ajax({" ascii
        $atob_func = "atob(" ascii
        $form_serialize = "$('form').serialize()" ascii
        $naver_css = "nid.naver.com" ascii
        $kakao_ref = "accounts.kakao.com" ascii
        $daum_ref = "logins.daum.net" ascii
        $cafe24_ref = "cafe24.com" ascii
        $count_check = /count\s*>=\s*2/ ascii
        $prevent_default = "e.preventDefault()" ascii
        $cross_domain = "crossDomain: true" ascii
        $atob_func and
        $form_serialize and
        $prevent_default and
        ($cross_domain or $count_check) and
        any of ($naver_css, $kakao_ref, $daum_ref, $cafe24_ref)
 * AncientNET / Zyre Botnet — YARA Detection Rules
 * Author: GHOST - Breakglass Intelligence
 * Date: 2026-04-07
 * Reference: https://intel.breakglass.tech/post/ancientnet-zyre-total-botnet-unmasking-via-an-open-webdav
rule AncientNET_Zyre_Bot_ELF {
        date = "2026-04-07"
        description = "Detects Zyre/zyreBot ELF samples used by the AncientNET DDoS-as-a-Service botnet (Gafgyt-derivative)"
        family = "Gafgyt"
        operation = "AncientNET"
        actor = "zyreeeee3"
        sample_sha256 = "b7fb5a5d78431abfee0b69d44a8c0181df8dd588bca93694890aa8b0a3c75ab7"
        $id1 = "zyreBot" ascii
        $id2 = "zyre" ascii fullword
        $cmd1 = "motd" ascii fullword
        $cmd2 = "handshake" ascii fullword
        $cmd3 = "bighandshake" ascii fullword
        $cmd4 = "pingjoin" ascii fullword
        $cmd5 = "longnames" ascii fullword
        $msg1 = "[+] Starting (%s)..." ascii
        $msg2 = "[!] Instance check failed" ascii
        $msg3 = "SPEED|" ascii
        $kill1 = "mirai." ascii
        $kill2 = "sora." ascii
        $kill3 = "hilix." ascii
        $kill4 = "rakitin." ascii
        $kill5 = "boatnet." ascii
        $kill6 = "owari." ascii
        $drop = "busybox wget" ascii
        $speed1 = "speedtest.tele2.net" ascii
        $speed2 = "cachefly.cachefly.net" ascii
        uint32(0) == 0x464c457f and (
            ($id1 and 2 of ($cmd*)) or
            (3 of ($cmd*) and 1 of ($msg*)) or
            ($id1 and 3 of ($kill*)) or
            (1 of ($msg*) and 1 of ($speed*) and $drop)
rule AncientNET_Zyre_Loader_Script {
        description = "Detects Zyre multi-arch loader shell scripts (cat.sh / bins.sh) used by AncientNET"
        sample_sha256 = "d32ff8801ab16f9025b132e70c5a15c6eb54f646e52cc5db08eeaab34deefc0e"
        $z1 = "zyre.arm4" ascii
        $z2 = "zyre.arm5" ascii
        $z3 = "zyre.arm6" ascii
        $z4 = "zyre.arm7" ascii
        $z5 = "zyre.mips" ascii
        $z6 = "zyre.mpsl" ascii
        $z7 = "zyre.x86" ascii
        $z8 = "zyre.x64" ascii
        $z9 = "zyre.spc" ascii
        $z10 = "zyre.sh4" ascii
        $ip = "103.130.214.71" ascii
        $path1 = "cd /tmp" ascii
        $path2 = "chmod +x" ascii
        4 of ($z*) and $ip and $path1 and $path2
rule AncientNET_C2_Source_srv_c {
        description = "Detects the AncientNET C2 server source code (srv.c) — leaked via open WebDAV on 103.130.214.71:4949"
        sample_sha256 = "3b85038b6d1d25af396e890179d7cec9e992df6801c7e089d322ad33a8ff16da"
        $brand1 = "AncientNET" ascii
        $lib1 = "libssh" ascii
        $lib2 = "civetweb" ascii
        $lib3 = "json-c" ascii
        $tier1 = "\"vip\"" ascii
        $tier2 = "\"basic\"" ascii
        $tier3 = "\"star\"" ascii
        $tier4 = "\"mirai\"" ascii
        $tier5 = "\"raw\"" ascii
        $tier6 = "\"spoof\"" ascii
        $f1 = "clients_cache.json" ascii
        $f2 = "creds.json" ascii
        $f3 = "rawmethods.json" ascii
        $f4 = "spoofmethods.json" ascii
        $discord = "discord.com/api/webhooks" ascii
        $paste = "pastebin.com/raw/" ascii
        $brand1 and $lib1 and $lib2 and 4 of ($tier*) and 2 of ($f*)
rule AncientNET_C2_Process_Single_Instance_Lock {
        description = "Heuristic: any Linux ELF binding TCP/58210 is overwhelmingly likely to be the AncientNET Zyre bot single-instance lock"
        note = "Use as a complement to net-level detection — process binding TCP/58210 should be triaged"
        $port_be = { E3 42 } // 58210 little-endian for htons
        $port_le = { 42 E3 }
        $bind = "bind" ascii
        $listen = "listen" ascii
        $id = "zyre" ascii
        uint32(0) == 0x464c457f and $id and ($port_be or $port_le) and $bind and $listen
rule CastleLoader_NSIS_Python_Dropper {
        date = "2026-04-09"
        description = "Detects CastleLoader NSIS installers with embedded Python runtime and AES-encrypted payload"
        hash = "4ba0d3ae41a0ae3143e8c2c3307c24b0d548593f97c79a30c0387b3d62504c31"
        family = "CastleLoader"
        actor = "GrayBravo"
        // NSIS header signature
        $nsis_magic = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
        // install.ini pattern (CastleLoader config)
        $install_ini = "package_name=data" ascii wide
        $install_path = "install_path=%TEMP%" ascii wide
        $vc_redist = "vc_redist" ascii wide nocase
        // Python runtime indicators
        $python_pdb = "pythonw.pdb" ascii
        $python314 = "python314" ascii wide
        $python_dll = "python3.dll" ascii wide
        // Padding/evasion indicators (junk SQLite databases)
        $sqlite_hdr = "SQLite format 3" ascii
        $pak_file = ".pak" ascii wide
        filesize > 10MB and
        $nsis_magic and
        ($install_ini or $install_path) and
        ($python_pdb or $python314 or $python_dll) and
        (#sqlite_hdr > 2 or $pak_file)
rule CastleLoader_NSIS_InstallINI {
        description = "Detects CastleLoader NSIS install.ini configuration pattern"
        $s1 = "[install]" ascii wide nocase
        $s2 = "package_name=" ascii wide
        $s3 = "install_path=" ascii wide
        $s4 = "run_as_admin=" ascii wide
        $pak = ".pak" ascii wide
        filesize < 1KB and
        $s1 and $s2 and $s3 and $s4 and $pak
rule CastleLoader_Signed_SERPENTINE {
        description = "Detects executables signed by fraudulent SERPENTINE SOLAR LIMITED certificate"
        $cert_cn = "SERPENTINE SOLAR LIMITED" ascii wide
        $cert_issuer = "Sectigo Public Code Signing CA EV R36" ascii wide
        any of ($cert*)
rule CastleLoader_Code_Signing_Certs {
        description = "Detects executables signed by known CastleLoader code signing certificates"
        $cert1 = "SERPENTINE SOLAR LIMITED" ascii wide
        $cert2 = "NOBIS LLC" ascii wide
        $cert3 = "LLC Territory of Comfort" ascii wide
rule Calipology_TrojanizedRustDesk_MSTeams {
        description = "Detects trojanized MSTeams installer distributing weaponized RustDesk, linked to calipology/Striker actor"
        hash = "d01148808fbeefa22cd4541cdaaee8bc1f74e3045302115dc5b08b99ff93dc9c"
        $s1 = "systemautoupdater.com" ascii wide
        $s2 = "mon.systemautoupdater.com" ascii wide
        $s3 = "MSTeamsSetup" ascii wide
        $s4 = "RustDesk" ascii wide
        $signer = "Zlatin Stamatov" ascii wide
        $certum = "Certum Code Signing 2021 CA" ascii wide
        uint16(0) == 0x5A4D and filesize < 20MB and (
            ($s1 or $s2) or
            ($s3 and $s4) or
            ($signer and $certum)
rule Calipology_CodeSigningCert {
        description = "Detects files signed with the Zlatin Stamatov certificate used by calipology actor"
        $serial = { 0f 97 17 73 c3 8e 4b 32 ac b1 21 85 51 51 ba a4 }
        uint16(0) == 0x5A4D and ($signer or $serial)
rule MSIL_Benin_Loader_AllSyDevs {
        date = "2026-04-10"
        description = "Detects MSIL/Benin loader variant from AllSyDevs C2 campaign"
        hash = "a888fb84a000df02eb54d7e63746609f4a348fd2026eef40c9198a42d1b3ee32"
        $dotnet = "v4.0.30319" ascii
        $asm = "Xngpwrsns" ascii wide
        $props = "Igkwxppl.Properties" ascii wide
        $aes = "AesCryptoServiceProvider" ascii wide
        $resource = "ResourceA" ascii wide
        $key1 = "7Am6AotaNR5hyDy3" ascii wide
        $key2 = "XeLjmrfAsUIojTZr" ascii wide
        $key3 = "2SUUCAP4yPDmWBy8" ascii wide
        $guid = { 56 66 87 A1 1C F2 71 40 A2 F2 25 C7 2D 15 CF BE }
        uint16(0) == 0x5A4D and filesize > 500KB and filesize < 1MB and $dotnet and ($asm or $props) and 2 of ($key1, $key2, $key3, $guid, $resource, $aes)
rule MSIL_Benin_Campaign_Generic {
        description = "Generic detection for MSIL/Benin AES process injection loaders"
        $marshal = "GetDelegateForFunctionPointer" ascii wide
        $k32a = "kernel32" ascii wide
        $k32b = { 6B 00 65 00 72 00 6E 00 65 00 6C 00 20 00 33 00 32 00 }
        uint16(0) == 0x5A4D and filesize > 400KB and filesize < 2MB and $dotnet and $aes and $marshal and $resource and 1 of ($k32a, $k32b)
  YARA Rules for CPUID.com Supply Chain Compromise
  Author: GHOST - Breakglass Intelligence
  Date: 2026-04-10
  Reference: https://intel.breakglass.tech
  TLP: WHITE
rule CPUID_Trojanized_Installer {
        description = "Detects the trojanized HWiNFO_Monitor_Setup installer from CPUID supply chain compromise"
        $s1 = "HWiNFO_Monitor_Setup" ascii wide
        $s2 = "HWiNFO" ascii wide
        $s3 = "HWMonitor" ascii wide
        $inno1 = "Inno Setup" ascii wide
        $inno2 = "JRSoftware" ascii wide
        $russian = {D0 A0 D1 83 D1 81} // "Rus" in UTF-8 Cyrillic
        ($s1 or ($s2 and $s3)) and
        ($inno1 or $inno2) and
        $russian
rule CPUID_CryptbaseDLL_Sideload {
        description = "Detects malicious cryptbase.dll used in CPUID supply chain compromise (Trojan.Alien)"
        hash = "9cdabd70f50dc8c03f0dfb31894d9d5265134a2cf07656ce8ad540c1790fc984"
        $name = "CRYPTBASE" ascii wide nocase
        $bios1 = "SMBIOS" ascii wide
        $bios2 = "SystemBiosVersion" ascii wide
        $vm1 = "VirtualBox" ascii wide
        $vm2 = "VMware" ascii wide
        $wmi1 = "Win32_BIOS" ascii wide
        $wmi2 = "SELECT * FROM" ascii wide nocase
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        filesize > 100KB and filesize < 5MB and
        $name and
        (2 of ($bios*, $vm*, $wmi*)) and
        1 of ($anti*)
rule FileZilla_VersionDLL_Sideload {
        description = "Detects malicious version.dll from FileZilla trojanization campaign (same group as CPUID)"
        hash = "e4c6f8ee8c946c6bd7873274e6ed9e41dec97e05890fa99c73f4309b60fd3da4"
        $doh1 = "dns-query" ascii wide
        $doh2 = "application/dns-message" ascii wide
        $doh3 = "1.1.1.1" ascii wide
        $bios1 = "SystemBiosVersion" ascii wide
        $bios2 = "Win32_BIOS" ascii wide
        $vm2 = "VBOX" ascii wide nocase
        filesize > 100KB and filesize < 2MB and
        1 of ($doh*) and
        1 of ($bios*) and
        (1 of ($vm*) or $anti1)
rule DLL_Sideload_NTDLL_Proxy_DotNET {
        description = "Detects DLL sideloading payload that proxies NTDLL through .NET assembly (generic)"
        $ntdll1 = "ntdll" ascii wide nocase
        $ntdll2 = "NtProtectVirtualMemory" ascii
        $ntdll3 = "NtAllocateVirtualMemory" ascii
        $ntdll4 = "NtWriteVirtualMemory" ascii
        $ntdll5 = "NtCreateThreadEx" ascii
        $dotnet1 = "mscoree.dll" ascii wide
        $dotnet2 = "_CorDllMain" ascii
        $dotnet3 = "v4.0.30319" ascii wide
        $dotnet4 = "System.Reflection" ascii wide
        $load1 = "Assembly.Load" ascii wide
        $load2 = "MemoryStream" ascii wide
        2 of ($ntdll*) and
        (1 of ($dotnet*) or 1 of ($load*))
// ============================================================
// Kharon/AdaptixC2 Agent — Breakglass Intelligence (2026-04-12)
// Campaign: 3-build spreader/service/DLL, operator :redxvz
rule GHOST_Kharon_C2_Agent {
        description = "Detects Kharon C2 agent for AdaptixC2 framework"
        date = "2026-04-12"
        hash1 = "8e3f7307deb54940e8bec734cd1760f9cfbe07d1f1bc33135cbaaa4959de43f3"
        hash2 = "6a20a6ed6385d19d401300ee00c516528bda7373fbbcd90e23b018bc020c2d6d"
        hash3 = "1c7cdc98e74642be9e2e55a7766ea711501b15dd30af3bb9686b57d1ad7dd3c7"
        $pipe = "kharon_pipe" wide ascii
        $attr = "maded_by=oblivion" wide ascii
        $agent = "agent_name=kharon" wide ascii
        $cmd1 = "go_inject" ascii
        $cmd2 = "go_poll" ascii
        $cmd3 = "go_kill" ascii
        $cmd4 = "go_list" ascii
        $cmd5 = "go_cleanup" ascii
        $srv = "CK_SRV" ascii
        $hb = "MSG_PP" ascii
        $op = ":redxvz" wide ascii
        $err1 = "CHUNK_READ_ERROR" ascii
        $err2 = "MAX_DOWNLOADS_REACHED" ascii
        $fnv_seed = { 8a 52 15 05 }
        $fnv_prime = { 93 01 00 01 }
            ($pipe and $agent) or
            ($attr) or
            ($pipe and 2 of ($cmd*)) or
            ($fnv_seed and $fnv_prime and 1 of ($cmd*)) or
            ($srv and $hb and 1 of ($cmd*)) or
            (3 of ($cmd*) and ($pipe or $srv))
rule GHOST_Kharon_Spreader_Variant {
        description = "Detects Kharon spreader variant with lateral movement capability"
        hash = "8e3f7307deb54940e8bec734cd1760f9cfbe07d1f1bc33135cbaaa4959de43f3"
        $smb1 = "ADMIN$" wide ascii
        $smb2 = "IPC$" wide ascii
        $scm = "OpenSCManager" ascii
        $wmi = "Win32_Process" wide ascii
        $winrm = "WinRM" wide ascii
        $inject = "RuntimeBroker.exe" wide ascii
        $pipe and
        1 of ($cmd*) and
        ($inject or 1 of ($smb*, $scm, $wmi, $winrm))
rule GHOST_DustExe_Novel_Sample {
        description = "Detects dust.exe sample (MD5: 5b347a6a5104d72a6592568a33778eb2) - novel Dust Specter variant"
        author = "GHOST Intelligence / Breakglass"
        date = "2026-04-24"
        hash_md5 = "5b347a6a5104d72a6592568a33778eb2"
        reference = "https://x.com/salmanvsf/status/1904438817064640583"
        hash.md5(0, filesize) == "5b347a6a5104d72a6592568a33778eb2"
rule GHOST_DustSpecter_C2_Indicators {
        description = "Detects Dust Specter C2 communication patterns (TWINTALK/GHOSTFORM)"
        reference = "Zscaler ThreatLabz - Dust Specter APT"
        $ua = "Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0" ascii wide
        $path1 = "C:\\ProgramData\\PolGuid" ascii wide nocase
        $path2 = "C:\\ProgramData\\WinWebex" ascii wide nocase
        $mutex = "Global\\__" ascii wide
        $dll1 = "libvlc.dll" ascii wide
        $dll2 = "hostfxr.dll" ascii wide
        $seed = { AB CD EF }
        $jwt_secret = "\"_\"" ascii
        $file1 = "in.txt" ascii wide
        $file2 = "out.txt" ascii wide
        $file3 = "programTemp.log" ascii wide
        $resource = "CheckFopil.PolGuid.zip" ascii wide
            ($ua and any of ($path*)) or
            ($mutex and any of ($dll*)) or
            ($resource) or
            ($seed and $jwt_secret) or
            (2 of ($file*) and any of ($path*))
rule GHOST_DustSpecter_SPLITDROP {
        description = "Detects SPLITDROP .NET dropper used by Dust Specter"
        reference = "Zscaler ThreatLabz"
        $aes = "AesCryptoServiceProvider" ascii
        $pbkdf = "Rfc2898DeriveBytes" ascii
        $path = "ProgramData\\PolGuid" ascii wide
        3 of ($resource, $aes, $pbkdf, $path)
rule GHOST_DustSpecter_GHOSTFORM_RAT {
        description = "Detects GHOSTFORM RAT used by Dust Specter"
        $opacity = "0.001" ascii wide
        $form_size1 = "10" ascii wide
        $form_size2 = "15" ascii wide
        $path_in = "in.txt" ascii wide
        $path_out = "out.txt" ascii wide
        $c2_domain1 = "lecturegenieltd.pro" ascii wide
        $c2_domain2 = "meetingapp.site" ascii wide
        $c2_domain3 = "afterworld.store" ascii wide
        $c2_domain4 = "girlsbags.shop" ascii wide
        $c2_domain5 = "onlinepettools.shop" ascii wide
        $c2_domain6 = "web14.info" ascii wide
        $c2_domain7 = "justweb.click" ascii wide
            ($mutex and ($path_in or $path_out)) or
            any of ($c2_domain*)
rule GhostMail_Zimbra_XSS_Payload {
        description = "Detects Operation GhostMail JavaScript payload targeting Zimbra Classic UI"
        author = "Breakglass Intelligence"
        reference = "https://www.seqrite.com/blog/operation-ghostmail-zimbra-xss-russian-apt-ukraine/"
        tlp = "TLP:CLEAR"
        apt = "APT28"
        campaign = "Operation GhostMail"
        $script_id = "zmb_pl_v3_" ascii wide
        $xor_key = "twichcba5e" ascii wide
        $soap_scratch = "GetScratchCodesRequest" ascii wide
        $soap_apppass = "CreateAppSpecificPasswordRequest" ascii wide
        $soap_identity = "GetIdentitiesRequest" ascii wide
        $soap_device = "GetDeviceStatusRequest" ascii wide
        $soap_oauth = "GetOAuthConsumersRequest" ascii wide
        $soap_prefs = "ModifyPrefsRequest" ascii wide
        $exfil_tgz = "/home/~/?fmt=tgz" ascii wide
        $appname = "ZimbraWeb" ascii wide
        $imap_enable = "zimbraPrefImapEnabled" ascii wide
        $c2_beacon = "SendStartPing" ascii wide
        $gather_2fa = "gather_2fa_codes" ascii wide
        $gather_email = "gather_email" ascii wide
        $gather_env = "gather_environment" ascii wide
        $checkpoint = "zd_comp_" ascii wide
        $script_id or
        ($xor_key and any of ($soap_*)) or
        (3 of ($soap_*) and $exfil_tgz) or
        ($appname and $imap_enable) or
        ($c2_beacon and any of ($gather_*)) or
        (4 of ($soap_*) and $checkpoint)
rule Zimbra_CVE_2025_48700_XSS_Import {
        description = "Detects CSS @import-based XSS payload targeting Zimbra CVE-2025-48700/CVE-2025-66376"
        cve = "CVE-2025-48700, CVE-2025-66376"
        $import_frag1 = "@import" ascii wide nocase
        $import_frag2 = "@im" ascii wide nocase
        $zimbra_csrf = "X-Zimbra-Csrf-Token" ascii wide
        $csrf_local = "csrfToken" ascii wide
        $classic_ui = "/zimbra/h/" ascii wide
        $soap_ns = "urn:zimbraAccount" ascii wide
        $soap_ns2 = "urn:zimbraMail" ascii wide
            ($import_frag1 and ($zimbra_csrf or $csrf_local)) or
            ($import_frag2 and any of ($soap_ns*)) or
            ($zimbra_csrf and $csrf_local and $classic_ui)
rule Zimbra_DNS_Exfil_GhostMail {
        description = "Detects DNS exfiltration pattern used in Operation GhostMail"
        $dns_pattern = /d-[a-z0-9]{12}\.[a-z0-9]+\.[A-Z2-7]{10,60}\.i\./ ascii
        $c2_domain = "zimbrasoft.com.ua" ascii wide nocase
        $base32_func = "base32" ascii wide nocase
        $dns_exfil = ".i.zimbrasoft" ascii wide nocase
   YARA Rules for Booking.com ClickFix NetSupport RAT Campaign
   Author: Breakglass Intelligence (GHOST)
   Date: 2026-04-25
   Reference: h/t @JAMESWT_WT
rule MSI_NetSupport_Booking_ClickFix {
        description = "Detects MSI installer delivering NetSupport RAT via Booking.com ClickFix campaign"
        date = "2026-04-25"
        hash = "46b7a1b85bcfcf536e6b479a6347150770021839664b1f03117db8a7d22771d3"
        campaign = "Booking ClickFix"
        $msi_header = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "7z Arch Package" ascii wide
        $s2 = "7z Technology" ascii wide
        $s3 = "altera.7z" ascii wide
        $s4 = "lnk.7z" ascii wide
        $s5 = "sysinfo" ascii wide
        $s6 = "grenworls" ascii wide
        $s7 = "limosik" ascii wide
        $vbs1 = "WScript.Shell" ascii wide
        $vbs2 = "ExpandEnvironmentStrings" ascii wide
        $vbs3 = "explorer.exe" ascii wide
        $product_code = "{4E52A15F-F46F-40FD-8EAF-58302ACA8A96}" ascii wide
        $upgrade_code = "{8F587F72-423C-40C1-8E7C-9FF50B1D8CE0}" ascii wide
        $msi_header at 0 and (
            ($s1 and $s2) or
            ($s3 and $s4 and $s5) or
            ($s6 and $s7) or
            $product_code or
            $upgrade_code
rule NetSupport_Client32_INI_BKS_C2 {
        description = "Detects NetSupport RAT client32.ini configured with bksnb/bksju C2 domains"
        hash_md5 = "c7c4568516bfe053f656549f4d97a1a5"
        $c2_primary = "bksnb.com" ascii wide nocase
        $c2_secondary = "bksju.com" ascii wide nocase
        $gsk = "GJ;C@HEKHN=OBFGK<E?MBNGM=CAPFA" ascii
        $section = "[HTTP]" ascii
        $gateway = "GatewayAddress" ascii
        $silent = "silent=1" ascii
        $skmode = "SKMode=1" ascii
        ($c2_primary or $c2_secondary) and ($section or $gateway) or
        $gsk
rule NetSupport_Sysinfo_LNK_Persistence {
        description = "Detects LNK shortcut for NetSupport RAT persistence via sysinfo.exe"
        hash = "0f3959a7698901fc59f090dcf314e5811e7d11ecef9a8828a0dea318543b02b2"
        $path1 = "sysinfo\\sysinfo.exe" ascii wide nocase
        $path2 = "ProgramData\\sysinfo" ascii wide nocase
        $machine = "vm-eb6a5926-adb" ascii wide nocase
        $lnk_header at 0 and ($path1 or $path2 or $machine)
rule NetSupport_RAT_Stealth_Config {
        description = "Detects NetSupport Manager configured for stealth/RAT operation"
        $ini_client = "[Client]" ascii
        $systray = "SysTray=0" ascii
        $showui = "ShowUIOnConnect=0" ascii
        $disable1 = "DisableChatMenu=1" ascii
        $disable2 = "DisableDisconnect=1" ascii
        $disable3 = "DisableRequestHelp=1" ascii
        $http = "[HTTP]" ascii
        $gateway = "GatewayAddress=" ascii
        $ini_client and $silent and $skmode and $systray and $http and $gateway and 2 of ($disable*)
rule NetSupport_Sysinfo_Loader {
        description = "Detects renamed NetSupport Manager client (sysinfo.exe) used as RAT loader"
        hash = "275e5b085534f64313b50cbdcb08ecd59c57d21c96bb937f140ee92a3d27f792"
        $export = "_NSMClient32@8" ascii
        $dll = "PCICL32.dll" ascii
        $manifest = "NetSupport Client Configurator" ascii wide
        $desc = "NetSupport Manager Remote Control" ascii wide
        $mz at 0 and $export and $dll and ($manifest or $desc)
rule Kimsuky_DDNS_Domain_Pattern {
        description = "Detects DNS queries or URLs referencing Kimsuky-associated Korean DDNS domains"
        author = "GHOST Intelligence (Breakglass)"
        reference = "https://hunt.io/blog/million-ok-naver-facade-kimsuky-tracking"
        actor = "Kimsuky / APT43"
        confidence = "high"
        $ddns1 = "n-e.kr" ascii wide nocase
        $ddns2 = "r-e.kr" ascii wide nocase
        $ddns3 = "o-r.kr" ascii wide nocase
        $ddns4 = "kro.kr" ascii wide nocase
        $ddns5 = "p-e.kr" ascii wide nocase
        $sub1 = "oscatower" ascii wide nocase
        $sub2 = "nooraeso" ascii wide nocase
        $sub3 = "bermates" ascii wide nocase
        $sub4 = "jungop" ascii wide nocase
        $sub5 = "brimo" ascii wide nocase
        $sub6 = "queosera2" ascii wide nocase
        $sub7 = "morotomot" ascii wide nocase
        $sub8 = "hayoungju" ascii wide nocase
        $sub9 = "jujeong" ascii wide nocase
        $sub10 = "docotot" ascii wide nocase
        $sub11 = "neratras2" ascii wide nocase
        $sub12 = "tradoam" ascii wide nocase
        $sub13 = "artisgo" ascii wide nocase
        any of ($sub*) or (2 of ($ddns*))
rule Kimsuky_C2_IP_216_158_235_97 {
        description = "Detects references to Kimsuky-associated IP 216.158.235.97"
        $ip1 = "216.158.235.97" ascii wide
        $ip2 = { D8 9E EB 61 }
        $hostname = "vps3362300.trouble-free.net" ascii wide nocase
rule Kimsuky_SSH_HostKey_Tracking {
        description = "Detects SSH host key fingerprints from Kimsuky server 216.158.235.97"
        $fp_rsa = "oZM0MHGZTZsDGMBaBI4WXNEn2RFYI6Z2++DwfWrMiNc" ascii
        $fp_ecdsa = "6d/pNprVfXbJJNtA+UqrzfNahGp9w2PptnntDv/LsUM" ascii
        $fp_ed25519 = "IiJy8mQiIt6o77SN9gj0eFtIsGw9rEX0/pVDFYVN0qA" ascii
rule Grandoreiro_C2_Domain_Pattern_Apr2026
{
        description = "Detects Grandoreiro C2 domain strings from April 2026 campaign"
        tlp = "clear"
        malware_family = "Grandoreiro"
        reference = "https://x.com/skocherhan"
        $d01 = "asgomd.com" ascii wide nocase
        $d02 = "nogomd.com" ascii wide nocase
        $d03 = "asgrsv.com" ascii wide nocase
        $d04 = "jpgrsv.com" ascii wide nocase
        $d05 = "nogrsv.com" ascii wide nocase
        $d06 = "acgrsv.com" ascii wide nocase
        $d07 = "decrsv.com" ascii wide nocase
        $d08 = "decrmd.com" ascii wide nocase
        $d09 = "acgomd.com" ascii wide nocase
        $d10 = "jpgomd.com" ascii wide nocase
        $ip  = "45.227.254.10" ascii wide
rule Grandoreiro_C2_DGA_Pattern_Apr2026
        description = "Detects Grandoreiro DGA naming pattern: [prefix][suffix].com"
        $prefix1 = "asg" ascii wide nocase
        $prefix2 = "nog" ascii wide nocase
        $prefix3 = "jpg" ascii wide nocase
        $prefix4 = "acg" ascii wide nocase
        $prefix5 = "dec" ascii wide nocase
        $suffix1 = "omd.com" ascii wide nocase
        $suffix2 = "rsv.com" ascii wide nocase
        $suffix3 = "rmd.com" ascii wide nocase
        any of ($prefix*) and any of ($suffix*)
rule Grandoreiro_RDP_Cert_D538
        description = "Detects RDP certificate fingerprint from Grandoreiro C2 server D-538"
        $cert_cn = "D-538" ascii wide
        $cert_serial = { 61 fd f0 1e f8 cf fa 8a 4a 41 a0 68 06 2f 12 9a }
rule Phish_SharePoint_IPFS_Redirector
        description = "SharePoint phishing page that redirects to IPFS-hosted credential harvester"
        author = "Breakglass Intelligence / GHOST"
        reference = "cksredi.pages.dev"
        hash = "a570c993350761d7a92167d35e4fc2ab9fc91d15b4c2f0edf9b8b6bab209c288"
        $title = "<title>Sharepoint</title>" ascii nocase
        $noindex = "NOINDEX, NOFOLLOW" ascii
        $atob_call = "window.atob(" ascii
        $ipfs_b64 = "aXBmcy5ldGgu" ascii
        $ipfs_path = "/ipfs/Qm" ascii nocase
        $aragon = "aragon.network" ascii nocase
        $hash_split = "window.location.hash" ascii
        $redirect = "window.top.location.href" ascii
        $sp_logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAWkAAAFlCA" ascii
        $favicon_wp = "wp-includes/pomo" ascii
        $setTimeout = "setTimeout(message" ascii
        $title and
        (2 of ($atob_call, $ipfs_b64, $ipfs_path, $aragon)) and
        (2 of ($hash_split, $redirect, $sp_logo, $favicon_wp, $setTimeout))
rule Phish_IPFS_Redirector_Generic
        description = "Generic phishing page using IPFS for second-stage hosting via base64-encoded redirect"
        $atob1 = "window.atob(" ascii
        $atob2 = "atob(" ascii
        $ipfs1 = "/ipfs/" ascii
        $ipfs2 = "ipfs" ascii nocase
        $redirect1 = "window.top.location.href" ascii
        $redirect2 = "window.location.href" ascii
        $hash = "window.location.hash" ascii
        $noindex = "NOINDEX" ascii nocase
        $b64img = "data:image/png;base64," ascii
        $setTimeout = "setTimeout" ascii
        (1 of ($atob*)) and
        (1 of ($ipfs*)) and
        (1 of ($redirect*)) and
        $hash and
        $setTimeout
rule Phish_SharePoint_CloudflarePages_IPFS_Redirect
        description = "Detects SharePoint phishing redirector using Cloudflare Pages and IPFS"
        $template_var = "##email65##" ascii
        $atob_redirect = "window.atob(" ascii
        $ipfs_b64 = "aXBmcy5ldGguYXJhZ29uLm5ldHdvcms" ascii
        $getProcessHash = "getProcessHash" ascii
        $location_hash = "window.location.hash" ascii
        $signInBg = "signInBg" ascii
        $sk_fading = "sk-fading-circle" ascii
        $loader = "loaderBlock" ascii
        $wp_pomo = "wp-includes/pomo/i/" ascii
        $title and ($atob_redirect or $ipfs_b64) and 2 of ($template_var, $getProcessHash, $location_hash, $signInBg, $sk_fading, $loader, $wp_pomo, $noindex)
rule Phish_SharePoint_IPFS_Generic
        description = "Generic detection for SharePoint phishing with IPFS redirect pattern"
        $sharepoint = "Sharepoint" ascii nocase
        $atob = "atob(" ascii
        $ipfs1 = "ipfs" ascii nocase
        $ipfs2 = "/ipfs/" ascii
        $ipfs3 = "Qm" ascii
        $location_href = "location.href" ascii
        $hash_split = "hash.split" ascii
        $hidden_body = "display: none" ascii
        $email_template1 = "##email" ascii
        $email_template2 = "emailValue" ascii
        filesize < 1MB and $sharepoint and $atob and ($ipfs1 or $ipfs2 or $ipfs3) and $location_href and 2 of ($hash_split, $setTimeout, $hidden_body, $email_template1, $email_template2)
rule PhishKit_DeviceCode_Kali365 {
        description = "Microsoft OAuth Device Code phishing kit using kali365 C2"
        reference = "premiumauto-com-skocherhan-20260425-f41e-d7c01f40"
        severity = "high"
        tlp = "white"
        $api_domain = "api.kali365.xyz" ascii wide
        $api_path = "/api/status/" ascii wide
        $redirect_var = "REDIRECT_URL" ascii
        $loading_docs = "loadingdocuments" ascii wide
        $device_auth = "oauth2/deviceauth" ascii wide
        $sharepoint_fake = "SharePoint" ascii
        $status_captured = "captured" ascii
        $status_pending = "pending" ascii
        $copy_code = "navigator.clipboard.writeText" ascii
        $ms_login = "login.microsoftonline.com" ascii wide
        $preview_mode = "preview=true" ascii
        ($api_domain or $loading_docs) and ($device_auth or $ms_login) and 2 of ($status_captured, $status_pending, $copy_code, $sharepoint_fake)
rule PhishKit_ProposalBidLure {
        description = "Phishing landing page using Proposal/Bid document lure with redirect"
        severity = "medium"
        $title = "Proposal & Bid Documents" ascii wide nocase
        $secure = "Secure Access" ascii wide nocase
        $redirect = "REDIRECT_URL" ascii
        $preview = "PREVIEW_MODE" ascii
        $bot_check = "botPatterns" ascii
        $select_all = "selectAll" ascii
        $file_item = "file-item" ascii
        $view_selected = "viewSelected" ascii
        $title and $redirect and 3 of ($secure, $preview, $bot_check, $select_all, $file_item, $view_selected)
rule PhishKit_DeviceCode_Generic {
        description = "Generic Microsoft OAuth Device Code phishing page"
        $ms_device = "microsoftonline.com/common/oauth2/deviceauth" ascii wide
        $ms_device2 = "microsoft.com/devicelogin" ascii wide
        $copy_clipboard = "navigator.clipboard.writeText" ascii
        $poll_status = "pollStatus" ascii
        $sharepoint = "SharePoint" ascii
        $user_code = "userCode" ascii
        $verification = "Verification code" ascii nocase
        $steps_view = "Steps to view" ascii nocase
        ($ms_device or $ms_device2) and $copy_clipboard and 2 of ($poll_status, $sharepoint, $user_code, $verification, $steps_view)
    SpiceRAT C2 Detection Rules
    Investigation: 31.58.220.250 / jer.piexlt.com
    Date: 2026-04-26
    Author: GHOST / Breakglass Intelligence
    Reference: https://hunt.io/blog/the-secret-ingredient-unearthing-suspected-spicerat-infrastructure-via-html-response
    Reference: https://blog.talosintelligence.com/new-spicerat-sneakychef/
rule SpiceRAT_DLL_Exports
        description = "Detects SpiceRAT DLL by characteristic export function names"
        author = "GHOST / Breakglass Intelligence"
        date = "2026-04-26"
        malware_family = "SpiceRAT"
        threat_actor = "SneakyChef"
        severity = "HIGH"
        $export1 = "GetFullLangFileNameW2" ascii
        $export2 = "WinHttpPostShare" ascii
        $export3 = "WinHttpFreeShareFree" ascii
        2 of ($export*)
rule SpiceRAT_C2_HTTP_Response
        description = "Detects SpiceRAT C2 server HTTP response fingerprint"
        reference = "SHA-1: df608e9587f37a5d7f13deaa99d312b4acda463c"
        $response = "<HTML>RESPONSE</HTML>" ascii
        $confirm = "<HTML>D_OK<HTML>" ascii
rule SpiceRAT_C2_Network_Beacon
        description = "Detects SpiceRAT C2 beacon prefix in network traffic"
        $beacon_prefix = "wG." ascii
        $html_wrapper = "<HTML>" ascii
        $beacon_prefix and $html_wrapper
rule SpiceRAT_Campaign_Domains_2026
        description = "Detects references to SpiceRAT C2 domains from this investigation"
        investigation = "31-58-220-250-skocherhan"
        $d1 = "jer.piexlt.com" ascii nocase
        $d2 = "piexlt.com" ascii nocase
        $d3 = "zeosshop.ir" ascii nocase
        $d4 = "main.zeosshop.ir" ascii nocase
        $d5 = "master.zeosshop.ir" ascii nocase
        $d6 = "servers.zeosshop.ir" ascii nocase
rule SpiceRAT_Known_C2_Domains
        description = "Detects known SpiceRAT/SneakyChef C2 domain references"
        $d1 = "update.telecom-tm.com" ascii nocase
        $d2 = "webmail.roundcube.email" ascii nocase
        $d3 = "update.mozilia-tm.com" ascii nocase
        $d4 = "stock.adobe-service.net" ascii nocase
        $d5 = "zone.webskype.net" ascii nocase
        $d6 = "site.yoshlar.info" ascii nocase
        $d7 = "account.drive-google-com.tk" ascii nocase
        $d8 = "account.gommask.online" ascii nocase
rule SpiceRAT_Delivery_RAR_LNK
        description = "Detects RAR archives potentially delivering SpiceRAT via LNK files"
        $rar_magic = { 52 61 72 21 1A 07 }
        $lnk_sig = { 4C 00 00 00 01 14 02 00 }
        $dll_ref1 = "GetFullLangFileNameW2" ascii wide
        $dll_ref2 = "WinHttpPostShare" ascii wide
        $rar_magic at 0 and ($lnk_sig or any of ($dll_ref*))
rule WP_Domain_Renewal_Phish_Login {
        description = "WordPress domain renewal phishing kit - login page"
        author = "Breakglass Intelligence (GHOST)"
        reference = "https://malwr-analysis.com/2025/12/31/fake-wordpress-domain-renewal-phishing-email-stealing-credit-card-and-3-d-secure-otp/"
        filetype = "html"
        $title = "Log In \xe2\x80\x94 WordPress.com" ascii wide
        $form_class = "login-form" ascii
        $send_login = "send_login.php" ascii
        $wp_brand = "wp-brand-font" ascii
        $redirect = "window.location.href = 'index.php'" ascii
        $s1 = "Helper: send login to Telegram" ascii
        $s2 = "is-section-login" ascii
        $s3 = "one-login__footer" ascii
        $title and ($send_login or $s1) and any of ($form_class, $wp_brand, $redirect, $s2, $s3)
rule WP_Domain_Renewal_Phish_Payment {
        description = "WordPress domain renewal phishing kit - payment/card page"
        $title = "Secure order validation" ascii wide
        $merchant = "Wordpress Inc" ascii
        $ref = "VCSdom-3138303" ascii
        $send_payment = "send_payment.php" ascii
        $send_sms = "send_sms.php" ascii
        $3dsecure = "3D Secure Verification" ascii
        $sms_modal = "sms-modal" ascii
        $vercel = "hebbkx1anhila5yf.public.blob.vercel-storage.com" ascii
        2 of ($title, $merchant, $ref, $3dsecure) and any of ($send_payment, $send_sms, $sms_modal, $vercel)
rule WP_Domain_Renewal_Phish_Script {
        description = "WordPress domain renewal phishing kit - exfiltration JavaScript"
        filetype = "javascript"
        $v0_payment = "[v0] Payment data sent to Telegram" ascii
        $v0_sms = "[v0] SMS code sent to Telegram" ascii
        $v0_error = "[v0] Error sending payment data" ascii
        $verify_fail = "Verification failed. Please try again." ascii
        $card_fields = "cardholderName" ascii
        $sms_code = "smsCode" ascii
        any of ($v0_payment, $v0_sms) or (($send_payment or $send_sms) and ($verify_fail or $card_fields or $sms_code))
rule MAL_LNK_PowerShell_Downloader_Check_ZIP {
        description = "Detects malicious LNK files with obfuscated PowerShell that downloads Check.zip"
        author = "GHOST/Breakglass Intelligence"
        date = "2026-04-27"
        hash = "5cbe2a8f6ca1640d56423195ad5823c37df1fb2db882dfc1f08de745b084d337"
        tlp = "AMBER"
        reference = "38.76.199.112 open directory investigation"
        $ps_bypass = "-ep Bypass" wide ascii
        $ps_nop = "-NoP" wide ascii
        $char_obfusc1 = "[char](50*2+4)" wide ascii
        $char_obfusc2 = "[char](100+16)" wide ascii
        $char_obfusc3 = "[char]((20*5)+12)" wide ascii
        $tycheck = "tyCheck" wide ascii
        $hidden_exe = "Hidden.exe" wide ascii
        $hidden_vbs = "Hidden.vbs" wide ascii
        $lnk_header at 0 and 2 of ($ps_*, $char_*, $tycheck, $hidden_exe, $hidden_vbs)
rule MAL_VBS_Persistence_OpenCL_Rust {
        description = "Detects VBScript persistence mechanism using OpenCL_Rust registry key"
        hash = "fa7c8b4a0a3fdc499d17a95b16ece24db76d54dd782c1e93c046b9979c49075c"
        $vbs_shell = "WScript.Shell" ascii wide
        $reg_run = "CurrentVersion\\Run" ascii wide
        $opencl_rust = "OpenCL_Rust" ascii wide
        $security_check = "SecurityCheck" ascii wide
        $python = "python.exe" ascii wide
        $appdata = "%APPDATA%" ascii wide
rule MAL_DLL_Sideload_msedge_MinGW {
        description = "Detects trojanized msedge.dll compiled with MinGW for DLL sideloading"
        hash = "cce80cbbb34442c3006bd29042f70b5e40de6afec92f9edb0e62b5fe5783c0de"
        $mingw = "libgcc_s_dw2-1.dll" ascii
        $mingw_pthread = "mingw-w64-libraries/winpthreads" ascii
        $msedge_name = "msedge.dll" ascii wide
        $lark_cert = "Lark Technologies" ascii
        $get_temp = "GetTempPathA" ascii
        $debug_check = "IsDebuggerPresent" ascii
        $mingw and $msedge_name and
        2 of ($lark_cert, $get_temp, $debug_check, $mingw_pthread)
rule MAL_Infostealer_CookieExporter_Sideload {
        description = "Detects the cookie_exporter.exe being used as DLL sideloading host"
        hash = "aca33bafde0ed5677ecbe357c2547708e353bdcc8c45beec7fd1af82ceffedbd"
        $pdb = "cookie_exporter.exe.pdb" ascii
        $export = "ExportSpartanCookies" ascii
        $msedge_dep = "msedge.dll" ascii wide
        $ms_cert = "Microsoft Corporation" ascii
        $pdb and $export and $msedge_dep
rule MAL_Campaign_TCBIA007 {
        description = "Detects files associated with campaign TCBIA007"
        $campaign = "TCBIA007" ascii wide
        $tycheck = "tyCheck" ascii wide
        $security_check_path = "SecurityCheck\\python.exe" ascii wide
    YARA Rules for Odyssey Stealer (macOS)
    Author: GHOST Intelligence / Breakglass Intelligence
    Date: 2026-04-27
    Reference: GHOST-2026-0427-ODYSSEY
rule Odyssey_Stealer_AppleScript_Payload
        description = "Detects Odyssey Stealer obfuscated AppleScript payload"
        author = "GHOST Intelligence"
        malware_family = "Odyssey Stealer"
        platform = "macOS"
        severity = "critical"
        reference = "https://censys.com/blog/odyssey-stealer-inside-a-macos-crypto-stealing-operation/"
        $obf_func = /f\d{17}/ ascii
        $obf_var = /v\d{17}/ ascii
        $concat = "& return &" ascii
        $keychain = "login.keychain-db" ascii
        $exfil_zip = "/tmp/out.zip" ascii
        $curl_post = "curl -X POST" ascii
        $dscl = "dscl . authonly" ascii
        $security_ga = {73 65 63 75 72 69 74 79 [0-20] 2D 67 61}
        $electrum = ".electrum/wallets" ascii
        $exodus = "Application Support/Exodus" ascii
        $ledger = "Application Support/Ledger Live" ascii
        $trezor = "Application Support/@trezor" ascii
        (2 of ($obf_func, $obf_var, $concat)) and
        (2 of ($keychain, $exfil_zip, $curl_post, $dscl, $security_ga)) and
        (1 of ($electrum, $exodus, $ledger, $trezor))
rule Odyssey_Stealer_SOCKS5_Proxy
        description = "Detects Odyssey Stealer SOCKS5 proxy binary (Go, universal Mach-O)"
        hash = "d254125912d9e9e5c271766bc4f6eea0c296ad2c0cf19d4bd57081d1bf10f044"
        $go_socks = "github.com/armon/go-socks5" ascii
        $go_yamux = "github.com/hashicorp/yamux" ascii
        $chost = ".chost" ascii
        $botid = ".botid" ascii
        $mach_universal = { CA FE BA BE 00 00 00 02 }
        uint32(0) == 0xBEBAFECA and
        ($go_socks or $go_yamux) and
        ($chost and $botid)
rule Odyssey_Stealer_Trojanized_Wallet
        description = "Detects Odyssey Stealer trojanized cryptocurrency wallet applications"
        $swift = "SwiftUI" ascii
        $webkit = "WebKit" ascii
        $appkit = "AppKit" ascii
        $ledger_path = "Ledger Live" ascii wide
        $trezor_path = "Trezor Suite" ascii wide
        $wallet_exfil = "/log" ascii
        $c2_join = "/api/v1/bot/joinsystem" ascii
        $c2_actions = "/api/v1/bot/actions" ascii
        ($swift or $webkit or $appkit) and
        ($ledger_path or $trezor_path) and
        (1 of ($wallet_exfil, $c2_join, $c2_actions))
rule Odyssey_Stealer_C2_Communication
        description = "Detects Odyssey Stealer C2 communication patterns in network traffic or scripts"
        $api_join = "/api/v1/bot/joinsystem/" ascii
        $api_actions = "/api/v1/bot/actions/" ascii
        $api_repeat = "/api/v1/bot/repeat/" ascii
        $exfil_log = "/log" ascii
        $payload_d = /\/d\/[a-z]+\d+/ ascii
        $otherassets = "/otherassets/" ascii
        $header_cl = "cl: 0" ascii
        $header_cn = "cn: 0" ascii
        $header_buildid = "buildid" ascii
        2 of ($api_join, $api_actions, $api_repeat, $exfil_log, $otherassets) or
        (1 of ($api_join, $api_actions, $api_repeat) and 1 of ($header_cl, $header_cn, $header_buildid))
rule Odyssey_Stealer_LaunchDaemon_Persistence
        description = "Detects Odyssey Stealer LaunchDaemon persistence plist"
        $plist_header = "<?xml version" ascii
        $plist_dtd = "PropertyList" ascii
        $label_pattern = /com\.\d{5}/ ascii
        $launch_daemon = "LaunchDaemons" ascii
        $run_at_load = "RunAtLoad" ascii
        $keep_alive = "KeepAlive" ascii
        $plist_header and $plist_dtd and $label_pattern and
        ($run_at_load or $keep_alive)
rule Odyssey_Stealer_ClickFix_Delivery
        description = "Detects Odyssey Stealer ClickFix delivery page HTML"
        $b64_curl_1 = "Y3VybCAtcyBodHRw" ascii
        $b64_curl_2 = "Y3VybCAtcy" ascii
        $b64_bash = "YmFzaCA" ascii
        $clipboard = "navigator.clipboard" ascii
        $osdetect = "navigator.platform" ascii
        $macos_check = "MacIntel" ascii
        $captcha = "CAPTCHA" ascii nocase
        $verify = "Verify" ascii
        $base64_decode = "base64 -d" ascii
        (1 of ($b64_curl_1, $b64_curl_2)) and
        (1 of ($clipboard, $base64_decode)) and
        (1 of ($captcha, $verify, $macos_check, $osdetect))
rule Odyssey_Stealer_Panel_HTML
        description = "Detects Odyssey Stealer admin panel HTML"
        severity = "informational"
        $meta_odyssey = "Odyssey - Advanced Dashboard" ascii
        $meta_macos = "MacOS - Advanced Dashboard" ascii
        $favicon_hash = "9108dde25ad958b27f6a97d644775dee" ascii
rule Odyssey_Stealer_Host_Artifacts
        description = "Detects Odyssey Stealer host artifacts on disk"
        $botid_file = ".botid" ascii
        $chost_file = ".chost" ascii
        $pwd_file = ".pwd" ascii
        $username_file = ".username" ascii
        $lastaction = ".lastaction" ascii
        $uninstalled = ".uninstalled" ascii
        $tmp_socks = "/tmp/socks" ascii
        $tmp_out = "/tmp/out.zip" ascii
        $tmp_ledger = "/tmp/ledger.zip" ascii
        $lovemrtrump = "lovemrtrump" ascii
rule GHOST_VBS_Downloader_ScreenShot_Lure {
        description = "Detects VBS downloader using Screen_Shot filename lure with string reversal obfuscation"
        reference = "GHOST-2026-0427-IMGRESIM"
        hash1 = "ff9e3a65c1925b0e8f1627488ee8b1f92e4f2dbc9d20a10edfd1b034e1a9d30a"
        $s1 = "StrReverse" ascii nocase
        $s2 = "MSXML2.XMLHTTP" ascii nocase
        $s3 = "Execute Extract" ascii nocase
        $s4 = "WScript.Shell" ascii nocase
        $s5 = "i//:sptth" ascii
        $marker1 = "GHGHDJKFGJKDFGHJDGJKDHGIUYDGDJKHLGDHJKLGDT" ascii
        $marker2 = "DYTYUFGJGHFGHJDFJKSHFHJKSFGJHGSJHKGSHJKGHJKM" ascii
        $url_frag = "en.misergm" ascii
        ($s1 and $s2 and $s3) and
        ($marker1 or $marker2 or $url_frag)
rule GHOST_VBS_Stage2_PiriformIGo_Dropper {
        description = "Detects stage 2 VBS dropper creating PiriformIGo persistence"
        hash1 = "62104db9fc64c8d5910f58d517d2cc4a5072709200a2f93c011f687f4a293ddd"
        $persist1 = "PiriformIGo" ascii nocase
        $persist2 = "ChromeReportUpdate" ascii nocase
        $persist3 = "Google-Chrome-Reporting" ascii nocase
        $schtask = "schtasks /Create" ascii nocase
        $interval = "/SC MINUTE /MO 1" ascii nocase
        $c2_1 = "dekontara" ascii nocase
        $c2_2 = "STARTGO" ascii nocase
        $c2_3 = "GOSTARTWORKSVB" ascii nocase
        $marker1 = "--TEGO20" ascii
        $marker2 = "--TOGO20" ascii
        (2 of ($persist*)) and
        ($schtask or $interval) and
        (1 of ($c2*) or 1 of ($marker*))
rule GHOST_JPEG_Embedded_VBS_Payload {
        description = "Detects JPEG files with VBS payload appended after custom markers"
        hash1 = "b7a7a2d39764bc569a01c95da80592ce8d68ff0e5223ccbe69100d699dd09906"
        $jpeg = { FF D8 FF }
        $vbs1 = "CreateObject" ascii
        $vbs2 = "Execute" ascii
        $vbs3 = "WScript" ascii
        $jpeg at 0 and
        ($marker1 or $marker2) and
        (1 of ($vbs*))
rule GHOST_VBS_Dekontara_C2 {
        description = "Detects VBS scripts communicating with dekontara.digital C2"
        $c2 = "dekontara.digital" ascii nocase
        $path = "STARTGO" ascii
        $work = "GOSTARTWORKSVB" ascii
        $post = "POST" ascii
        $xml = "MSXML2" ascii nocase
        $c2 and
        (1 of ($path, $work)) and
        ($post or $xml)
rule MAL_Distribution_Lesoulkir_Info_2026
        description = "Detects network indicators related to lesoulkir.info malware distribution infrastructure"
        reference = "https://x.com/smica83/status/2048702700435411434"
        confidence = "medium"
        $domain1 = "lesoulkir.info" ascii wide nocase
        $domain2 = "lesoulkir" ascii wide nocase
        $filename = "photo-123621198" ascii wide nocase
        any of ($domain*) or $filename
rule smishing_panda_shop_kr_http_403_gate
        description = "Detects Panda Shop / Smishing Triad phishing kit HTTP 403 gating response"
        reference = "https://twitter.com/skocherhan"
        campaign = "Panda Shop Korea Smishing"
        hash = "1b52ddb86fde13b3439e18ee444c5b218791eced9b582a8aa5214cfa491c35fe"
        $access_denied = "<h2>Access Denied</h2>" ascii
        $header_403 = "HTTP/1.1 403 Forbidden" ascii
        $keepalive = "Keep-Alive: timeout=5" ascii
        $access_denied and ($header_403 or $keepalive)
rule smishing_panda_shop_domain_pattern
        description = "Detects domain patterns used in Panda Shop Korean smishing campaign"
        $d1 = "urgent-notice-check.click" ascii nocase
        $d2 = "digital-post.live" ascii nocase
        $d3 = "digital-notice-kr.sbs" ascii nocase
        $d4 = "appleviewer.sbs" ascii nocase
        $d5 = "edeliever-address-verify.biz" ascii nocase
        $d6 = "epdf-user-view.quest" ascii nocase
        $d7 = "official-notice.click" ascii nocase
        $d8 = "public-revenue-info.biz" ascii nocase
        $ip = "152.32.243.224" ascii
rule smishing_kr_domain_naming_convention
        description = "Heuristic detection for Korean smishing domain naming patterns"
        $p1 = /digital-notice-[a-z]{2}\.(sbs|click|biz|quest|live)/ ascii nocase
        $p2 = /urgent-notice-[a-z]+\.(sbs|click|biz|quest|live)/ ascii nocase
        $p3 = /official-notice\.(sbs|click|biz|quest|live)/ ascii nocase
        $p4 = /[a-z]+-address-verify\.(sbs|click|biz|quest|live)/ ascii nocase
        $p5 = /[a-z]+-user-view\.(sbs|click|biz|quest|live)/ ascii nocase
        $p6 = /public-revenue-[a-z]+\.(sbs|click|biz|quest|live)/ ascii nocase
