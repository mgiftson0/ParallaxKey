Add-Type -AssemblyName System.Drawing
$source = "c:\Users\mgift\OneDrive\Desktop\vault\src\assets\icons\icon-master.png"
$sizes = @(16, 32, 48, 128)

foreach ($s in $sizes) {
    $dest = "c:\Users\mgift\OneDrive\Desktop\vault\src\assets\icons\icon-$s.png"
    $img = [System.Drawing.Image]::FromFile($source)
    $bmp = New-Object System.Drawing.Bitmap($s, $s)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($img, 0, 0, $s, $s)
    $bmp.Save($dest, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    $img.Dispose()
    Write-Host "Generated $dest"
}
