<#
.SYNOPSIS
    Build script for Nexus Task Manager
#>

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   Building Nexus Task Manager (Win32)   " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Check if g++ is available in the system PATH
if (!(Get-Command g++ -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] 'g++' compiler not found in PATH. Please install MinGW-w64." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Compiler detected successfully." -ForegroundColor Yellow
Write-Host "[INFO] Preparing source files and backend configurations..." -ForegroundColor Yellow

$sources = @(
    "taskmanager.cpp",
    "imgui/imgui.cpp",
    "imgui/imgui_draw.cpp",
    "imgui/imgui_tables.cpp",
    "imgui/imgui_widgets.cpp",
    "imgui/imgui_impl_win32.cpp",
    "imgui/imgui_impl_opengl3.cpp"
)

$output = "Forensictaskmanager.exe"
$includes = "-Iimgui", "-I."
$libs = "-lopengl32", "-lgdi32", "-luser32", "-lshell32", "-lpsapi", "-lole32", "-luuid"

Write-Host "[INFO] Compiling source code and linking Win32 / OpenGL libraries..." -ForegroundColor Yellow

& g++ @sources -o $output @includes @libs -static-libgcc -static-libstdc++

if ($LASTEXITCODE -eq 0) {
    Write-Host "-----------------------------------------" -ForegroundColor Green
    Write-Host " [SUCCESS] Build completed successfully!   " -ForegroundColor Green
    Write-Host " [INFO] Executable generated: .\$output    " -ForegroundColor Cyan
    Write-Host "-----------------------------------------" -ForegroundColor Green
    
    Write-Host "Launching Forensic task manager..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    .\$output
} else {
    Write-Host "-----------------------------------------" -ForegroundColor Red
    Write-Host " [ERROR] Compilation failed with errors. " -ForegroundColor Red
    Write-Host "-----------------------------------------" -ForegroundColor Red
    exit $LASTEXITCODE
}
