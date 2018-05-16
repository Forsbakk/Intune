$ChocoPkgs = @(
    @{
        Name = "googlechrome"
        Mode = "install"
    },
    @{
        Name = "firefox"
        Mode = "install"
    },
    @{
        Name = "notepadplusplus"
        Mode = "install"
    },
    @{
        Name = "7zip"
        Mode = "install"
    },
    @{
        Name = "sccmtoolkit"
        Mode = "install"
    }
)
$ChocoPkgs | ConvertTo-Json -Compress | Out-File config.json