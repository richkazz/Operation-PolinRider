/*
 * polinrider-complete.yar - unified YARA ruleset for PolinRider / BeaverTail / Glassworm
 */

rule PolinRider_V2_VersionTag {
    meta:
        description = "PolinRider variant 2 per-injection version tag"
        severity    = "critical"
        campaign    = "PolinRider"
    strings:
        $v_sequential = /global\[.{0,3}_V.{0,3}\]\s*=\s*.{0,3}8-st\d{1,3}/
        $v_numeric    = /global\[.{0,3}_V.{0,3}\]\s*=\s*.{0,3}8-\d{3,4}/
    condition:
        any of them
}

rule PolinRider_V1_Marker {
    meta:
        description = "PolinRider variant 1 rmcej_otb injection marker"
        severity    = "critical"
        campaign    = "PolinRider"
    strings:
        $marker = /rmcej.{0,5}otb/
    condition:
        $marker
}

rule BeaverTail_BlockchainC2 {
    meta:
        description = "BeaverTail blockchain dead-drop C2 endpoint"
        severity    = "critical"
        campaign    = "PolinRider / BeaverTail"
    strings:
        $tron    = "api.trongrid.io"              ascii wide
        $aptos   = "fullnode.mainnet.aptoslabs.com" ascii wide
        $bsc     = "bsc-dataseed"                 ascii wide
        $solana  = "api.mainnet-beta.solana.com"  ascii wide
        $aptos2  = "aptos-mainnet.nodereal"       ascii wide
    condition:
        any of them
}

rule BeaverTail_Stage1_Loader {
    meta:
        description = "BeaverTail stage-1 obfuscated loader (eval + base64)"
        severity    = "critical"
        campaign    = "PolinRider / BeaverTail"
    strings:
        $eval_buf  = /eval\s*\(\s*Buffer\.from\s*\(/ ascii
        $eval_atob = /eval\s*\(\s*atob\s*\(/         ascii
    condition:
        any of them
}

rule Glassworm_InvisibleUnicode {
    meta:
        description = "Invisible Unicode characters used to hide payload (Glassworm)"
        severity    = "critical"
        campaign    = "PolinRider / Glassworm"
    strings:
        $zwsp  = { E2 80 8B }   // U+200B Zero-width space
        $zwj   = { E2 80 8D }   // U+200D Zero-width joiner
        $bom   = { EF BB BF }   // U+FEFF BOM mid-file
        $vs1   = { EF B8 80 }   // U+FE00 Variation Selector-1
        $vs2   = { EF B8 81 }   // U+FE01 Variation Selector-2
        $rtlo  = { E2 80 AE }   // U+202E Right-to-Left Override
    condition:
        2 of them
        and (
            filename matches /\.(js|mjs|ts|py|rb|sh|cjs)$/i
        )
}

rule BinaryExtension_JavaScript_Payload {
    meta:
        description = "JavaScript code stored in a binary-extension file (font/image disguise)"
        severity    = "critical"
        campaign    = "PolinRider font vector"
    strings:
        $iife_open   = "(function("   ascii
        $iife_open2  = "!function("   ascii
        $var_decl    = "var _0x"      ascii
        $eval_open   = "eval("        ascii
        $require_    = "require('"    ascii
        $process_env = "process.env"  ascii
        $buf_from    = "Buffer.from(" ascii
    condition:
        (
            filename matches /\.(woff2?|ttf|otf|eot|png|jpg|jpeg|gif|ico|bmp|webp|mp3|mp4)$/i
        )
        and (
            not (
                uint32(0) == 0x32464F77 or  // wOF2 (77 4F 46 32)
                uint32(0) == 0x46464F77 or  // wOFF (77 4F 46 46)
                uint32(0) == 0x4F54544F or  // OTTO
                uint32(0) == 0x00010000 or  // TTF
                uint32(0) == 0x474E5089 or  // PNG
                uint16(0) == 0xD8FF         // JPEG
            )
        )
        and any of ($iife_open, $iife_open2, $var_decl, $eval_open, $require_, $process_env, $buf_from)
}

rule TasksJson_FontPayload_Execution {
    meta:
        description = "VS Code tasks.json configured to execute a font/binary-extension file with Node.js"
        severity    = "critical"
        campaign    = "PolinRider TasksJacker + font vector"
    strings:
        $node_woff2  = /node\s+[^\s"']*\.woff2/ ascii
        $node_woff   = /node\s+[^\s"']*\.woff/  ascii
        $node_ttf    = /node\s+[^\s"']*\.ttf/   ascii
        $node_png    = /node\s+[^\s"']*\.png/   ascii
        $folder_open = "\"folderOpen\""          ascii
        $hide_true   = "\"hide\": true"          ascii
    condition:
        any of ($node_woff2, $node_woff, $node_ttf, $node_png)
        and ($folder_open or $hide_true)
}

rule BeaverTail_ShuffleCipher_Decoder {
    meta:
        description = "4-layer shuffle-cipher decoder pattern"
        severity    = "high"
        campaign    = "PolinRider / BeaverTail"
    strings:
        $charcode_chain = /String\.fromCharCode\(\d+(,\s*\d+){14,}/
        $xor_map = /\.split\(.\)\.map.*\.charCodeAt.*\^/
    condition:
        any of them
}
