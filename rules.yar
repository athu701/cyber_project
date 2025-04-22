rule ExampleMalwareRule
{
    meta:
        description = "Detects suspicious strings"
        author = "YourName"
        date = "2025-04-18"
    
    strings:
        $s1 = "malware"
        $s2 = "suspicious"
        $s3 = "backdoor"
    
    condition:
        any of them
}
