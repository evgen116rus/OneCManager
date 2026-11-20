// OneCManager - поиск, удаление и установка версий 1С:Предприятие на удалённых ПК.
// Сборка: MSVC (см. .github/workflows/build.yml), кодировка исходника UTF-8 (/utf-8).
//
// Способы удалённого запуска:
//   1) стандартный: WMI (Win32_Process.Create) + msiexec на удалённом ПК;
//   2) запасной:    pse.exe (переименованный psexec) с именем службы -r ps_1C.
// Поиск версий: удалённый реестр (RemoteRegistry), запасной вариант - PowerShell через pse.exe.

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <cstdlib>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ---------------------------------------------------------------- данные / GUI id

struct Product {
    std::wstring name, version, key, arch;
    bool msi = false;
};

enum {
    IDC_HOST = 101, IDC_SCAN, IDC_METHOD, IDC_LIST, IDC_UNINST, IDC_CHKALL,
    IDC_SRC, IDC_ARGS, IDC_COPY, IDC_INST, IDC_LOG
};
enum { WM_LOG = WM_APP + 1, WM_SCANDONE, WM_JOBDONE };

static HWND g_wnd, hHostLbl, hHost, hScan, hMethodLbl, hMethod, hList, hUninst, hChkAll,
            hSrcLbl, hSrc, hArgsLbl, hArgs, hCopy, hInst, hLog;
static std::vector<Product> g_products;
static bool g_busy = false;

static const wchar_t* DEFAULT_ARGS =
    L"/qn /norestart TRANSFORMS=adminstallrelogon.mst;1049.mst DESIGNERALLCLIENTS=1 THICKCLIENT=1 "
    L"THINCLIENTFILE=1 THINCLIENT=1 WEBSERVEREXT=0 SERVER=0 CONFREPOSSERVER=0 CONVERTER77=0 "
    L"SERVERCLIENT=0 LANGUAGES=RU";

static const wchar_t* REMOTE_TMP = L"C:\\Windows\\Temp";
static const wchar_t* REMOTE_SETUP_DIR = L"C:\\Windows\\Temp\\1C_Setup";

// ---------------------------------------------------------------- утилиты

static void Log(const std::wstring& s) {
    PostMessageW(g_wnd, WM_LOG, 0, (LPARAM) new std::wstring(s));
}

static std::wstring ErrText(DWORD code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring r;
    if (n && buf) { r = buf; LocalFree(buf); }
    while (!r.empty() && (r.back() == L'\r' || r.back() == L'\n' || r.back() == L' ')) r.pop_back();
    wchar_t hex[32];
    wsprintfW(hex, L" (0x%08X)", code);
    return r + hex;
}

static std::wstring Trim(std::wstring s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::wstring Dec(const std::string& s, UINT cp) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(cp, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(cp, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::vector<std::wstring> Split(const std::wstring& s, wchar_t sep) {
    std::vector<std::wstring> r;
    size_t p = 0;
    for (;;) {
        size_t q = s.find(sep, p);
        if (q == std::wstring::npos) { r.push_back(s.substr(p)); break; }
        r.push_back(s.substr(p, q - p));
        p = q + 1;
    }
    return r;
}

static bool Is1C(std::wstring n) {
    for (auto& c : n) if (c == 0x0421 || c == 0x0441) c = L'c';   // кириллическая С/с -> латинская c
    if (!n.empty()) CharLowerBuffW(&n[0], (DWORD)n.size());
    size_t p = n.find(L"1c");
    if (p == std::wstring::npos) return false;
    return n.find(L"предприятие", p) != std::wstring::npos || n.find(L"enterprise", p) != std::wstring::npos;
}

static bool IsGuid(const std::wstring& k) { return k.size() >= 3 && k.front() == L'{' && k.back() == L'}'; }

static std::wstring FindPse() {
    wchar_t p[MAX_PATH];
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring d = p;
    d = d.substr(0, d.find_last_of(L'\\') + 1) + L"pse.exe";
    if (GetFileAttributesW(d.c_str()) != INVALID_FILE_ATTRIBUTES) return d;
    wchar_t f[MAX_PATH];
    if (SearchPathW(nullptr, L"pse.exe", nullptr, MAX_PATH, f, nullptr)) return f;
    return L"";
}

// Запуск процесса со скрытым окном, сбор stdout+stderr. started=false, если запустить не удалось.
static int RunCapture(const std::wstring& cmd, std::string& out, bool& started) {
    SECURITY_ATTRIBUTES sa{ sizeof sa, nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    started = false;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = nul; si.hStdOutput = wr; si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) { CloseHandle(rd); return -1; }
    started = true;
    char tmp[4096]; DWORD n;
    while (ReadFile(rd, tmp, sizeof tmp, &n, nullptr) && n) out.append(tmp, n);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
    return (int)ec;
}

static void LogTail(const std::string& out, UINT cp, int maxLines = 12) {
    auto lines = Split(Dec(out, cp), L'\n');
    std::vector<std::wstring> v;
    for (auto& l : lines) { auto t = Trim(l); if (!t.empty()) v.push_back(t); }
    size_t from = v.size() > (size_t)maxLines ? v.size() - maxLines : 0;
    for (size_t i = from; i < v.size(); ++i) Log(L"    " + v[i]);
}

static std::string B64(const std::string& s) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto u = [](char c) { return (unsigned)(unsigned char)c; };
    std::string o;
    size_t i = 0;
    for (; i + 2 < s.size(); i += 3) {
        unsigned v = (u(s[i]) << 16) | (u(s[i + 1]) << 8) | u(s[i + 2]);
        o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += t[v & 63];
    }
    if (i + 1 == s.size()) {
        unsigned v = u(s[i]) << 16;
        o += t[v >> 18]; o += t[(v >> 12) & 63]; o += "==";
    } else if (i + 2 == s.size()) {
        unsigned v = (u(s[i]) << 16) | (u(s[i + 1]) << 8);
        o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += '=';
    }
    return o;
}

// ---------------------------------------------------------------- WMI

struct Bstr {
    BSTR b;
    explicit Bstr(const wchar_t* s) { b = SysAllocString(s); }
    ~Bstr() { SysFreeString(b); }
    operator BSTR() const { return b; }
};

static void Blanket(IUnknown* p) {
    CoSetProxyBlanket(p, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
}

struct Wmi {
    IWbemServices* svc = nullptr;
    ~Wmi() { if (svc) svc->Release(); }

    bool Connect(const std::wstring& host, std::wstring& err) {
        IWbemLocator* loc = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc);
        if (FAILED(hr)) { err = ErrText(hr); return false; }
        Bstr ns((L"\\\\" + host + L"\\root\\cimv2").c_str());
        hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
        loc->Release();
        if (FAILED(hr)) { err = L"WMI: " + ErrText(hr); svc = nullptr; return false; }
        Blanket(svc);
        return true;
    }

    bool Create(const std::wstring& cmd, DWORD& pid, std::wstring& err) {
        IWbemClassObject *cls = nullptr, *inDef = nullptr, *inst = nullptr, *out = nullptr;
        Bstr clsName(L"Win32_Process"), mName(L"Create");
        bool ok = false;
        HRESULT hr = svc->GetObject(clsName, 0, nullptr, &cls, nullptr);
        if (SUCCEEDED(hr)) hr = cls->GetMethod(mName, 0, &inDef, nullptr);
        if (SUCCEEDED(hr)) hr = inDef->SpawnInstance(0, &inst);
        if (SUCCEEDED(hr)) {
            VARIANT v; VariantInit(&v);
            v.vt = VT_BSTR; v.bstrVal = SysAllocString(cmd.c_str());
            hr = inst->Put(L"CommandLine", 0, &v, 0);
            VariantClear(&v);
        }
        if (SUCCEEDED(hr)) hr = svc->ExecMethod(clsName, mName, 0, nullptr, inst, &out, nullptr);
        if (FAILED(hr)) {
            err = L"WMI: " + ErrText(hr);
        } else {
            VARIANT rv, pv; VariantInit(&rv); VariantInit(&pv);
            out->Get(L"ReturnValue", 0, &rv, nullptr, nullptr);
            out->Get(L"ProcessId", 0, &pv, nullptr, nullptr);
            if (rv.lVal != 0) err = L"Win32_Process.Create вернул код " + std::to_wstring(rv.lVal);
            else { pid = (DWORD)pv.lVal; ok = true; }
            VariantClear(&rv); VariantClear(&pv);
        }
        if (out) out->Release();
        if (inst) inst->Release();
        if (inDef) inDef->Release();
        if (cls) cls->Release();
        return ok;
    }

    bool Alive(DWORD pid) {
        std::wstring q = L"SELECT ProcessId FROM Win32_Process WHERE ProcessId=" + std::to_wstring(pid);
        Bstr lang(L"WQL"), qs(q.c_str());
        IEnumWbemClassObject* e = nullptr;
        if (FAILED(svc->ExecQuery(lang, qs, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &e))) return false;
        Blanket(e);
        IWbemClassObject* o = nullptr;
        ULONG n = 0;
        e->Next(10000, 1, &o, &n);
        if (o) o->Release();
        e->Release();
        return n > 0;
    }
};

static long ReadRc(const std::wstring& unc) {
    HANDLE h = CreateFileW(unc.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    char b[64] = {};
    DWORD n = 0;
    ReadFile(h, b, sizeof b - 1, &n, nullptr);
    CloseHandle(h);
    DeleteFileW(unc.c_str());
    if (n == 0) return -1;
    return atol(b);
}

// ---------------------------------------------------------------- удалённый запуск

// rc: код возврата (-1 - неизвестен). Возвращает false, если запустить не удалось.
static bool ExecRemote(const std::wstring& host, int method, const std::wstring& prog, const std::wstring& args, long& rc) {
    rc = -1;
    if (method != 2) {
        std::wstring err;
        Wmi w;
        if (w.Connect(host, err)) {
            std::wstring rcUnc = L"\\\\" + host + L"\\C$\\Windows\\Temp\\1c_ps.rc";
            DeleteFileW(rcUnc.c_str());
            std::wstring cmd = L"cmd /v:on /c \"start /wait \"\" " + prog + L" " + args +
                               L" & echo !errorlevel! >" + REMOTE_TMP + L"\\1c_ps.rc\"";
            DWORD pid = 0;
            if (w.Create(cmd, pid, err)) {
                Log(L"  запущено через WMI (msiexec), PID " + std::to_wstring(pid) + L", ожидание завершения...");
                for (int i = 0; i < 1800 && w.Alive(pid); ++i) Sleep(3000);
                rc = ReadRc(rcUnc);
                return true;
            }
        }
        Log(L"  стандартный запуск (WMI) не удался: " + err);
        if (method == 1) return false;
        Log(L"  переключаюсь на pse.exe -r ps_1C");
    }
    std::wstring pse = FindPse();
    if (pse.empty()) { Log(L"  pse.exe не найден (положите рядом с программой или в PATH)"); return false; }
    std::string out;
    bool started = false;
    int ec = RunCapture(L"\"" + pse + L"\" \\\\" + host + L" -accepteula -nobanner -r ps_1C -s " + prog + L" " + args, out, started);
    if (!started) { Log(L"  не удалось запустить pse.exe"); return false; }
    Log(L"  выполнено через pse.exe");
    LogTail(out, CP_OEMCP, 6);
    rc = ec;
    return true;
}

static bool ReportRc(long rc) {
    if (rc == 0) { Log(L"  результат: успешно"); return true; }
    if (rc == 3010 || rc == 1641) { Log(L"  результат: успешно, требуется перезагрузка (код " + std::to_wstring(rc) + L")"); return true; }
    if (rc == -1) { Log(L"  результат: код возврата неизвестен, проверьте список и лог C:\\Windows\\Temp\\1c_ps.log на ПК"); return false; }
    Log(L"  результат: ОШИБКА, код " + std::to_wstring(rc) + L" (лог: C:\\Windows\\Temp\\1c_ps.log на ПК)");
    return false;
}

// ---------------------------------------------------------------- поиск версий

static std::wstring RegStr(HKEY k, const wchar_t* name) {
    DWORD t = 0, sz = 0;
    if (RegQueryValueExW(k, name, nullptr, &t, nullptr, &sz) != 0 || (t != REG_SZ && t != REG_EXPAND_SZ)) return L"";
    std::wstring s(sz / 2 + 1, L'\0');
    if (RegQueryValueExW(k, name, nullptr, nullptr, (LPBYTE)&s[0], &sz) != 0) return L"";
    s.resize(wcslen(s.c_str()));
    return s;
}

// Служба "Удалённый реестр": тип запуска "Автоматически" + состояние "Запущена".
static void StartRemoteRegistry(const std::wstring& host) {
    SC_HANDLE m = OpenSCManagerW((L"\\\\" + host).c_str(), nullptr, SC_MANAGER_CONNECT);
    if (!m) { Log(L"  служба Remote Registry: нет доступа к диспетчеру служб: " + ErrText(GetLastError())); return; }
    SC_HANDLE s = OpenServiceW(m, L"RemoteRegistry", SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
    if (!s) {
        Log(L"  служба Remote Registry: не удалось открыть: " + ErrText(GetLastError()));
    } else {
        if (ChangeServiceConfigW(s, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                 nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
            Log(L"  служба Remote Registry: тип запуска - автоматически");
        else
            Log(L"  служба Remote Registry: не удалось задать автозапуск: " + ErrText(GetLastError()));
        SERVICE_STATUS st{};
        if (QueryServiceStatus(s, &st) && st.dwCurrentState != SERVICE_RUNNING) {
            if (!StartServiceW(s, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
                Log(L"  служба Remote Registry: не удалось запустить: " + ErrText(GetLastError()));
            for (int i = 0; i < 20; ++i) {
                if (QueryServiceStatus(s, &st) && st.dwCurrentState == SERVICE_RUNNING) break;
                Sleep(500);
            }
        }
        if (QueryServiceStatus(s, &st) && st.dwCurrentState == SERVICE_RUNNING)
            Log(L"  служба Remote Registry: запущена");
        CloseServiceHandle(s);
    }
    CloseServiceHandle(m);
}

static bool ScanRegistry(const std::wstring& host, std::vector<Product>& out, std::wstring& err) {
    HKEY hr = nullptr;
    std::wstring m = L"\\\\" + host;
    StartRemoteRegistry(host);   // в начале: автозапуск + запуск службы
    LONG r = RegConnectRegistryW(m.c_str(), HKEY_LOCAL_MACHINE, &hr);
    if (r != 0) { err = ErrText(r); return false; }
    for (int v = 0; v < 2; ++v) {
        REGSAM view = v == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
        HKEY ku;
        if (RegOpenKeyExW(hr, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ | view, &ku) != 0) continue;
        wchar_t sub[256];
        for (DWORD i = 0;; ++i) {
            DWORD n = 256;
            if (RegEnumKeyExW(ku, i, sub, &n, nullptr, nullptr, nullptr, nullptr) != 0) break;
            HKEY ks;
            if (RegOpenKeyExW(ku, sub, 0, KEY_READ | view, &ks) != 0) continue;
            std::wstring name = RegStr(ks, L"DisplayName");
            if (Is1C(name)) {
                bool dup = false;
                for (auto& p : out) if (p.key == sub) dup = true;
                if (!dup) {
                    Product p;
                    p.name = name; p.version = RegStr(ks, L"DisplayVersion"); p.key = sub;
                    p.arch = v == 0 ? L"x64" : L"x86";
                    DWORD wi = 0, sz = sizeof wi;
                    RegQueryValueExW(ks, L"WindowsInstaller", nullptr, nullptr, (LPBYTE)&wi, &sz);
                    p.msi = IsGuid(p.key) || wi == 1;
                    out.push_back(p);
                }
            }
            RegCloseKey(ks);
        }
        RegCloseKey(ku);
    }
    RegCloseKey(hr);
    return true;
}

static bool ScanPse(const std::wstring& host, std::vector<Product>& out, std::wstring& err) {
    std::wstring pse = FindPse();
    if (pse.empty()) { err = L"pse.exe не найден (положите рядом с программой или в PATH)"; return false; }
    std::wstring script =
        LR"PS([Console]::OutputEncoding=[Text.Encoding]::UTF8;
$k=@(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','x64'),@('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','x86'));
foreach($e in $k){Get-ItemProperty $e[0] -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match '1[CС]\s*:?\s*(Предприятие|Enterprise)'} | ForEach-Object {('{0}|{1}|{2}|{3}|{4}' -f $_.PSChildName,$_.DisplayName,$_.DisplayVersion,$e[1],$_.WindowsInstaller)}})PS";
    std::string bytes((const char*)script.data(), script.size() * sizeof(wchar_t));
    std::wstring cmd = L"\"" + pse + L"\" \\\\" + host + L" -accepteula -nobanner -r ps_1C -s powershell -NoProfile -NonInteractive "
                       L"-ExecutionPolicy Bypass -EncodedCommand " + Dec(B64(bytes), CP_ACP);
    std::string o;
    bool started = false;
    RunCapture(cmd, o, started);
    if (!started) { err = L"не удалось запустить pse.exe"; return false; }
    bool any = false;
    for (auto& line : Split(Dec(o, CP_UTF8), L'\n')) {
        auto f = Split(Trim(line), L'|');
        if (f.size() != 5) continue;
        any = true;
        Product p;
        p.key = f[0]; p.name = f[1]; p.version = f[2]; p.arch = f[3];
        p.msi = IsGuid(p.key) || f[4] == L"1";
        out.push_back(p);
    }
    if (!any && o.find("PsExec") != std::string::npos && o.find("1C") == std::string::npos) {
        // ничего не найдено - это нормально, но если pse вернул ошибку подключения, покажем её
        std::wstring t = Dec(o, CP_OEMCP);
        if (t.find(L"Couldn't") != std::wstring::npos || t.find(L"Access is denied") != std::wstring::npos ||
            t.find(L"not found") != std::wstring::npos) { err = Trim(t); return false; }
    }
    return true;
}

static void DoScan(const std::wstring& host, int method) {
    Log(L"Поиск установленных версий 1С на " + host + L" ...");
    std::vector<Product> v;
    std::wstring err;
    bool ok = false;
    if (method != 2) {
        ok = ScanRegistry(host, v, err);
        if (!ok) Log(L"  удалённый реестр недоступен: " + err);
    }
    if (!ok && method != 1) {
        Log(L"  поиск через pse.exe + PowerShell ...");
        v.clear();
        ok = ScanPse(host, v, err);
        if (!ok) Log(L"  ошибка: " + err);
    }
    if (ok) {
        std::sort(v.begin(), v.end(), [](const Product& a, const Product& b) { return a.name < b.name; });
        Log(L"Найдено версий: " + std::to_wstring(v.size()));
    } else {
        Log(L"Поиск не удался.");
    }
    PostMessageW(g_wnd, WM_SCANDONE, ok ? 1 : 0, (LPARAM) new std::vector<Product>(v));
}

// ---------------------------------------------------------------- удаление

static void DoUninstall(const std::wstring& host, int method, const std::vector<Product>& sel) {
    for (auto& p : sel) {
        Log(L"Удаление: " + p.name + L" " + p.version + L" " + p.key);
        if (!IsGuid(p.key)) { Log(L"  пропуск: не MSI-пакет (нет кода продукта {GUID})"); continue; }
        long rc = -1;
        if (ExecRemote(host, method, L"msiexec",
                       L"/x " + p.key + L" /qn /norestart /l*v " + REMOTE_TMP + L"\\1c_ps.log", rc))
            ReportRc(rc);
    }
    DoScan(host, method);
}

// ---------------------------------------------------------------- установка

static bool ResolveInstaller(std::wstring src, std::wstring& dir, std::wstring& file) {
    while (src.size() > 3 && src.back() == L'\\') src.pop_back();
    DWORD a = GetFileAttributesW(src.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    if (a & FILE_ATTRIBUTE_DIRECTORY) {
        dir = src;
        if (GetFileAttributesW((dir + L"\\1CEnterprise 8.msi").c_str()) != INVALID_FILE_ATTRIBUTES) { file = L"1CEnterprise 8.msi"; return true; }
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((dir + L"\\*.msi").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) { file = fd.cFileName; FindClose(h); return true; }
        if (GetFileAttributesW((dir + L"\\setup.exe").c_str()) != INVALID_FILE_ATTRIBUTES) { file = L"setup.exe"; return true; }
        return false;
    }
    size_t p = src.find_last_of(L'\\');
    if (p == std::wstring::npos) return false;
    dir = src.substr(0, p);
    file = src.substr(p + 1);
    return true;
}

static void DoInstall(const std::wstring& host, int method, const std::wstring& src, const std::wstring& userArgs, bool copy) {
    std::wstring dir, file;
    if (!ResolveInstaller(src, dir, file)) {
        Log(L"Установщик не найден или недоступен: " + src);
        return;
    }
    Log(L"Установка из: " + dir + L"\\" + file);
    std::wstring runDir = dir;
    std::wstring unc = L"\\\\" + host + L"\\C$\\Windows\\Temp\\1C_Setup";
    if (copy) {
        Log(L"  копирование дистрибутива на " + host + L" (robocopy)...");
        std::string out;
        bool st = false;
        int ec = RunCapture(L"robocopy \"" + dir + L"\" \"" + unc + L"\" /E /R:2 /W:3 /NP /NDL /NJH", out, st);
        if (!st || ec >= 8) {
            Log(L"  ошибка копирования (код " + std::to_wstring(ec) + L")");
            LogTail(out, CP_OEMCP, 8);
            return;
        }
        runDir = REMOTE_SETUP_DIR;
    }
    std::wstring path = runDir + L"\\" + file;
    std::wstring lower = file;
    CharLowerBuffW(&lower[0], (DWORD)lower.size());
    bool isMsi = lower.size() > 4 && lower.substr(lower.size() - 4) == L".msi";
    std::wstring prog, args;
    if (isMsi) {
        prog = L"msiexec";
        args = L"/i \"" + path + L"\" " + userArgs + L" /l*v " + REMOTE_TMP + L"\\1c_ps.log";
    } else {
        prog = L"\"" + path + L"\"";
        args = userArgs;
    }
    long rc = -1;
    if (ExecRemote(host, method, prog, args, rc)) ReportRc(rc);
    if (copy) {
        std::string out; bool st = false;
        RunCapture(L"cmd /c rd /s /q \"" + unc + L"\"", out, st);
        Log(L"  временная папка на ПК удалена");
    }
    DoScan(host, method);
}

// ---------------------------------------------------------------- GUI

static std::wstring GetText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(n + 1, L'\0');
    GetWindowTextW(h, &s[0], n + 1);
    s.resize(n);
    return s;
}

static std::wstring GetHost() {
    std::wstring h = Trim(GetText(hHost));
    while (!h.empty() && h.front() == L'\\') h.erase(h.begin());
    return h;
}

static void SetBusy(bool b) {
    g_busy = b;
    for (HWND h : { hHost, hScan, hMethod, hList, hUninst, hChkAll, hSrc, hArgs, hCopy, hInst })
        EnableWindow(h, !b);
}

template <class F>
static void RunJob(F f) {
    SetBusy(true);
    std::thread([f]() {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        f();
        CoUninitialize();
        PostMessageW(g_wnd, WM_JOBDONE, 0, 0);
    }).detach();
}

static void Layout(int w, int h) {
    int lh = std::max(100, (h - 230) / 2);
    MoveWindow(hHostLbl, 10, 14, 80, 20, TRUE);
    MoveWindow(hHost, 95, 10, 190, 24, TRUE);
    MoveWindow(hScan, 295, 9, 150, 26, TRUE);
    MoveWindow(hMethodLbl, 460, 14, 60, 20, TRUE);
    MoveWindow(hMethod, 520, 10, std::max(150, w - 530), 200, TRUE);
    MoveWindow(hList, 10, 44, w - 20, lh, TRUE);
    int y = 44 + lh + 6;
    MoveWindow(hUninst, 10, y, 200, 26, TRUE);
    MoveWindow(hChkAll, 220, y, 140, 26, TRUE);
    y += 36;
    MoveWindow(hSrcLbl, 10, y + 3, 85, 20, TRUE);
    MoveWindow(hSrc, 95, y, w - 105, 24, TRUE);
    y += 30;
    MoveWindow(hArgsLbl, 10, y + 3, 85, 20, TRUE);
    MoveWindow(hArgs, 95, y, w - 105, 24, TRUE);
    y += 32;
    MoveWindow(hCopy, 95, y + 2, std::max(200, w - 330), 22, TRUE);
    MoveWindow(hInst, w - 200, y, 190, 26, TRUE);
    y += 34;
    MoveWindow(hLog, 10, y, w - 20, std::max(40, h - y - 10), TRUE);
}

static void AppendLog(const std::wstring& s) {
    int n = GetWindowTextLengthW(hLog);
    SendMessageW(hLog, EM_SETSEL, n, n);
    SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)(s + L"\r\n").c_str());
}

static void FillList(const std::vector<Product>& v) {
    g_products = v;
    ListView_DeleteAllItems(hList);
    for (int i = 0; i < (int)v.size(); ++i) {
        LVITEMW it{};
        it.mask = LVIF_TEXT;
        it.iItem = i;
        it.pszText = (LPWSTR)v[i].name.c_str();
        ListView_InsertItem(hList, &it);
        ListView_SetItemText(hList, i, 1, (LPWSTR)v[i].version.c_str());
        ListView_SetItemText(hList, i, 2, (LPWSTR)v[i].arch.c_str());
        ListView_SetItemText(hList, i, 3, (LPWSTR)v[i].key.c_str());
    }
}

static HWND Mk(const wchar_t* cls, const wchar_t* text, DWORD style, int id, HWND parent, DWORD ex = 0) {
    HWND h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, parent,
                             (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return h;
}

static LRESULT CALLBACK WndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_wnd = hw;
        hHostLbl = Mk(L"STATIC", L"Компьютер:", 0, 0, hw);
        hHost = Mk(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, IDC_HOST, hw, WS_EX_CLIENTEDGE);
        SendMessageW(hHost, EM_SETCUEBANNER, TRUE, (LPARAM)L"имя ПК или IP");
        hScan = Mk(L"BUTTON", L"Найти версии 1С", WS_TABSTOP | BS_DEFPUSHBUTTON, IDC_SCAN, hw);
        hMethodLbl = Mk(L"STATIC", L"Способ:", 0, 0, hw);
        hMethod = Mk(L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, IDC_METHOD, hw);
        SendMessageW(hMethod, CB_ADDSTRING, 0, (LPARAM)L"Авто: WMI + msiexec, при отказе pse.exe");
        SendMessageW(hMethod, CB_ADDSTRING, 0, (LPARAM)L"Только стандартные средства (WMI + msiexec)");
        SendMessageW(hMethod, CB_ADDSTRING, 0, (LPARAM)L"Только pse.exe -r ps_1C");
        SendMessageW(hMethod, CB_SETCURSEL, 0, 0);
        hList = Mk(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, IDC_LIST, hw, WS_EX_CLIENTEDGE);
        ListView_SetExtendedListViewStyle(hList, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        const wchar_t* cols[] = { L"Название", L"Версия", L"Разр.", L"Код продукта" };
        int widths[] = { 360, 120, 55, 270 };
        for (int i = 0; i < 4; ++i) {
            LVCOLUMNW c{};
            c.mask = LVCF_TEXT | LVCF_WIDTH;
            c.pszText = (LPWSTR)cols[i];
            c.cx = widths[i];
            ListView_InsertColumn(hList, i, &c);
        }
        hUninst = Mk(L"BUTTON", L"Удалить отмеченные", WS_TABSTOP, IDC_UNINST, hw);
        hChkAll = Mk(L"BUTTON", L"Отметить все", WS_TABSTOP, IDC_CHKALL, hw);
        hSrcLbl = Mk(L"STATIC", L"Установщик:", 0, 0, hw);
        hSrc = Mk(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, IDC_SRC, hw, WS_EX_CLIENTEDGE);
        SendMessageW(hSrc, EM_SETCUEBANNER, TRUE, (LPARAM)L"\\\\server\\share\\1c\\8.3.xx\\windows64\\1CEnterprise 8.msi (или папка)");
        hArgsLbl = Mk(L"STATIC", L"Параметры:", 0, 0, hw);
        hArgs = Mk(L"EDIT", DEFAULT_ARGS, WS_TABSTOP | ES_AUTOHSCROLL, IDC_ARGS, hw, WS_EX_CLIENTEDGE);
        hCopy = Mk(L"BUTTON", L"Копировать дистрибутив на ПК (C$) и удалить после", WS_TABSTOP | BS_AUTOCHECKBOX, IDC_COPY, hw);
        SendMessageW(hCopy, BM_SETCHECK, BST_CHECKED, 0);
        hInst = Mk(L"BUTTON", L"Установить", WS_TABSTOP, IDC_INST, hw);
        hLog = Mk(L"EDIT", L"", WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, IDC_LOG, hw, WS_EX_CLIENTEDGE);
        SendMessageW(hLog, EM_SETLIMITTEXT, 4000000, 0);
        return 0;
    }
    case WM_SIZE:
        Layout(LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO*)lp)->ptMinTrackSize = { 760, 560 };
        return 0;
    case WM_LOG: {
        auto* s = (std::wstring*)lp;
        AppendLog(*s);
        delete s;
        return 0;
    }
    case WM_SCANDONE: {
        auto* v = (std::vector<Product>*)lp;
        if (wp) FillList(*v);
        delete v;
        return 0;
    }
    case WM_JOBDONE:
        SetBusy(false);
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (g_busy || HIWORD(wp) != BN_CLICKED) return 0;
        int method = (int)SendMessageW(hMethod, CB_GETCURSEL, 0, 0);
        std::wstring host = GetHost();
        if (id == IDC_SCAN || id == IDC_UNINST || id == IDC_INST) {
            if (host.empty()) { MessageBoxW(hw, L"Введите имя удалённого компьютера.", L"1С Менеджер", MB_ICONWARNING); return 0; }
        }
        if (id == IDC_SCAN) {
            RunJob([host, method] { DoScan(host, method); });
        } else if (id == IDC_CHKALL) {
            int n = ListView_GetItemCount(hList);
            bool all = true;
            for (int i = 0; i < n; ++i) if (!ListView_GetCheckState(hList, i)) all = false;
            for (int i = 0; i < n; ++i) ListView_SetCheckState(hList, i, !all);
        } else if (id == IDC_UNINST) {
            std::vector<Product> sel;
            std::wstring names;
            for (int i = 0; i < ListView_GetItemCount(hList) && i < (int)g_products.size(); ++i)
                if (ListView_GetCheckState(hList, i)) { sel.push_back(g_products[i]); names += L"\n - " + g_products[i].name + L" " + g_products[i].version; }
            if (sel.empty()) { MessageBoxW(hw, L"Отметьте галочками версии для удаления.", L"1С Менеджер", MB_ICONINFORMATION); return 0; }
            if (MessageBoxW(hw, (L"Удалить на " + host + L":" + names).c_str(), L"Подтверждение", MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
            RunJob([host, method, sel] { DoUninstall(host, method, sel); });
        } else if (id == IDC_INST) {
            std::wstring src = Trim(GetText(hSrc)), args = Trim(GetText(hArgs));
            bool copy = SendMessageW(hCopy, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (src.empty()) { MessageBoxW(hw, L"Укажите путь к установщику (msi/exe или папка).", L"1С Менеджер", MB_ICONWARNING); return 0; }
            if (MessageBoxW(hw, (L"Установить на " + host + L" из:\n" + src).c_str(), L"Подтверждение", MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
            RunJob([host, method, src, args, copy] { DoInstall(host, method, src, args, copy); });
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int show) {
    INITCOMMONCONTROLSEX ic{ sizeof ic, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&ic);
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"OneCManagerWnd";
    RegisterClassW(&wc);
    HWND w = CreateWindowExW(0, wc.lpszClassName, L"1С:Предприятие - удалённое обнаружение, удаление и установка",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 920, 720, nullptr, nullptr, hi, nullptr);
    ShowWindow(w, show);
    UpdateWindow(w);
    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(w, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
    }
    CoUninitialize();
    return 0;
}
