/* Peaklight Ransomware */

rule M_AES_Encrypted_payload {
   meta:
      author = "MAS"
      reference = "https://www.mandiant.com/"
      description = "This rule is desgined to detect on events that exhibits indicators of utilizing AES encryption for payload obfuscation."
      target_entity = "Process"
  strings:
    $a = /(\$\w+\.Key(\s|)=((\s|)(\w+|));|\$\w+\.Key(\s|)=(\s|)\w+\('\w+'\);)/
    $b = /\$\w+\.IV/
    $c = /System\.Security\.Cryptography\.(AesManaged|Aes)/
  condition:
    all of them
}

rule M_Downloader_PEAKLIGHT_1 {
   meta:
      author = "MAS"
      reference = "https://www.mandiant.com/"
      description = "This rule is designed to detect events related to Peaklight. PEAKLIGHT is an obfuscated PowerShell-based downloader which checks for the presence of hard-coded filenames and downloads files from a remote CDN if the files are not present."
      category = "Malware"
   strings:
      $str1 = /function\s{1,16}\w{1,32}\(\$\w{1,32},\s{1,4}\$\w{1,32}\)\{\[IO\.File\]::WriteAllBytes\(\$\w{1,32},\s{1,4}\$\w{1,32}\)\}/ ascii wide 
      $str2 = /Expand-Archive\s{1,16}-Path\s{1,16}\$\w{1,32}\s{1,16}-DestinationPath/ ascii wide
      $str3 = /\(\w{1,32}\s{1,4}@\((\d{3,6},){3,12}/ ascii wide
      $str4 = ".DownloadData(" ascii wide
      $str5 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12" ascii wide
      $str6 = /\.EndsWith\(((["']\.zip["'])|(\(\w{1,32}\s{1,16}@\((\d{3,6},){3}\d{3,6}\)\)))/ ascii wide
      $str7 = "Add -Type -Assembly System.IO.Compression.FileSystem" ascii wide
     $str8 = "[IO.Compression.ZipFile]::OpenRead"
   condition:
     4 of them and filesize < 10KB         
}

/* BrainCipher Ransomware */

rule BrainCipher_ransomware {
   meta:
      description = "Brain Cipher ransomware executable detection"
      author = "Aishat Motunrayo Awujola"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-01-20"
    hash1= "eb82946fa0de261e92f8f60aa878c9fef9ebb34fdababa66995403b110118b12"

  strings:
      $s1 = "L%nu%s\"^6" fullword ascii
      $s2 = "D$PWSP" fullword ascii /* Goodware String - occurred 1 times */
      $s3 = "2'2b2v2" fullword ascii /* Goodware String - occurred 1 times */
      $s4 = "Loyn?P00" fullword ascii
      $s5 = "4f5l5x5~5" fullword ascii /* Goodware String - occurred 1 times */
      $s6 = "4 444u4" fullword ascii /* Goodware String - occurred 1 times */
      $s7 = "wSYM ,9" fullword ascii
      $s8 = "=V=\\={=" fullword ascii /* Goodware String - occurred 1 times */
      $s9 = "5E6L6S6Z6" fullword ascii /* Goodware String - occurred 1 times */
      $s10 = ";&;P;_;" fullword ascii /* Goodware String - occurred 1 times */
      $s11 = "?0N0]0l0" fullword ascii /* Goodware String - occurred 1 times */
      $s12 = "9D$$ua" fullword ascii /* Goodware String - occurred 2 times */
      $s13 = "4.4=4L4" fullword ascii /* Goodware String - occurred 2 times */
      $s14 = "SQRVW3" fullword ascii
      $s15 = "_^ZY[]" fullword ascii /* Goodware String - occurred 3 times */
      $s16 = "?%U$38O" fullword ascii
      $s17 = "9&9,949" fullword ascii
      $s18 = "303M3W3" fullword ascii
      $s19 = "7+7:7I7H8R8z8" fullword ascii
      $s20 = "+D$H[_]^" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

/* BLX Stealer */

rule BLX_Stealer_rule {
    
    meta:
        description = "Detects BLX Stealer malware"
        author = "Wazuh"
        date = "2024-11-01"
        reference = "https://www.cyfirma.com/research/blx-stealer/"
        
    
    strings:
        $str0 = { 20 20 20 20 70 6f 6c 69 63 79 2e 6d 61 6e 69 66 65 73 74 2e 61 73 73 65 72 74 49 6e 74 65 67 72 69 74 79 28 6d 6f 64 75 6c 65 55 52 4c 2c 20 63 6f 6e 74 65 6e 74 29 3b }
        $str1 = { 20 20 41 72 72 61 79 50 72 6f 74 6f 74 79 70 65 53 68 69 66 74 2c }
        $str2 = { 20 20 69 66 20 28 21 73 74 61 74 65 2e 6b 65 65 70 41 6c 69 76 65 54 69 6d 65 6f 75 74 53 65 74 29 }
        $str3 = { 20 20 72 65 74 75 72 6e 20 72 65 71 75 69 72 65 28 27 74 6c 73 27 29 2e 44 45 46 41 55 4c 54 5f 43 49 50 48 45 52 53 3b }
        $str4 = { 21 47 7e 79 5f 3b }
        $str5 = { 3f 52 65 64 75 63 65 53 74 61 72 74 40 42 72 61 6e 63 68 45 6c 69 6d 69 6e 61 74 69 6f 6e 40 63 6f 6d 70 69 6c 65 72 40 69 6e 74 65 72 6e 61 6c 40 76 38 40 40 41 45 41 41 3f 41 56 52 65 64 75 63 74 69 6f 6e 40 32 33 34 40 50 45 41 56 4e 6f 64 65 40 32 33 34 40 40 5a }
        $str6 = { 40 55 56 57 48 }
        $str7 = { 41 49 5f 41 44 44 52 43 4f 4e 46 49 47 }
        $str8 = { 44 24 70 48 }
        $str9 = { 45 56 50 5f 4d 44 5f 43 54 58 5f 73 65 74 5f 75 70 64 61 74 65 5f 66 6e }
        $str10 = { 46 61 69 6c 65 64 20 74 6f 20 64 65 73 65 72 69 61 6c 69 7a 65 20 64 6f 6e 65 5f 73 74 72 69 6e 67 }
        $str11 = { 49 63 4f 70 }
        $str12 = { 54 24 48 48 }
        $str13 = { 5c 24 30 48 }
        $str14 = { 5c 24 58 48 }
        $str15 = { 64 24 40 48 }
        $str16 = { 67 65 74 73 6f 63 6b 6f 70 74 }
        $str17 = { 73 74 72 65 73 73 20 74 68 65 20 47 43 20 63 6f 6d 70 61 63 74 6f 72 20 74 6f 20 66 6c 75 73 68 20 6f 75 74 20 62 75 67 73 20 28 69 6d 70 6c 69 65 73 20 2d 2d 66 6f 72 63 65 5f 6d 61 72 6b 69 6e 67 5f 64 65 71 75 65 5f 6f 76 65 72 66 6c 6f 77 73 29 }
        $str18 = { 74 24 38 48 }
        $str19 = { 74 24 60 48 }
        
        $blx_stealer_network = "https://api.ipify.org" ascii wide nocase
        $blx_stealer_network1 = "https://geolocation-db.com" ascii wide nocase
        $blx_stealer_network2 = "https://discord.com/api/webhooks" ascii wide nocase
        
        $blx_stealer_hash1 = "8c4daf5e4ced10c3b7fd7c17c7c75a158f08867aeb6bccab6da116affa424a89"
        $blx_stealer_hash2 = "e74dac040ec85d4812b479647e11c3382ca22d6512541e8b42cf8f9fbc7b4af6"
        $blx_stealer_hash3 = "32abb4c0a362618d783c2e6ee2efb4ffe59a2a1000dadc1a6c6da95146c52881"
        $blx_stealer_hash4 = "5b46be0364d317ccd66df41bea068962d3aae032ec0c8547613ae2301efa75d6"

    condition:
        (all of ($str*) or any of ($blx_stealer_network*) or any of ($blx_stealer_hash*))

}