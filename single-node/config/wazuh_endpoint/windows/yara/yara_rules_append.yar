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