/* Fresh launcher derived from the pinned Sentinel launcher. Explicit UTF-8
 * preinitialization is required for Japanese JSON, paths and UI under LC_ALL=C.
 * Environment/site/CWD imports remain disabled. No Python.app is reused.
 */
#include <Python.h>
#include <mach-o/dyld.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void check(PyStatus status, PyConfig *config) {
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(config);
        Py_ExitStatusException(status);
    }
}

int main(int argc, char **argv) {
    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus prestatus = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(prestatus)) Py_ExitStatusException(prestatus);
    char raw[PATH_MAX], exe[PATH_MAX], root[PATH_MAX], zip[PATH_MAX], dyn[PATH_MAX];
    uint32_t capacity = sizeof(raw);
    if (_NSGetExecutablePath(raw, &capacity) || !realpath(raw, exe)) return 78;
    strcpy(root, exe);
    char *slash = strrchr(root, '/');
    if (!slash) return 78;
    *slash = '\0';
    const char *suffix = "/../Frameworks/Python.framework/Versions/3.14";
    if (strlen(root) + strlen(suffix) + 1 >= sizeof(raw)) return 78;
    strcpy(raw, root); strcat(raw, suffix);
    if (!realpath(raw, root)) return 78;
    if (snprintf(zip, sizeof(zip), "%s/Resources/python314.zip", root) >= sizeof(zip) ||
        snprintf(dyn, sizeof(dyn), "%s/Resources/lib-dynload", root) >= sizeof(dyn)) return 78;
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.site_import = 0;
    config.user_site_directory = 0;
    config.use_environment = 0;
    config.write_bytecode = 0;
    config.safe_path = 1;
    config.install_signal_handlers = 1;
    config.parse_argv = 1;
    check(PyConfig_SetBytesArgv(&config, argc, argv), &config);
    check(PyConfig_SetBytesString(&config, &config.program_name, exe), &config);
    check(PyConfig_SetBytesString(&config, &config.executable, exe), &config);
    check(PyConfig_SetBytesString(&config, &config.base_executable, exe), &config);
    check(PyConfig_SetBytesString(&config, &config.home, root), &config);
    check(PyConfig_SetBytesString(&config, &config.prefix, root), &config);
    check(PyConfig_SetBytesString(&config, &config.exec_prefix, root), &config);
    check(PyConfig_SetBytesString(&config, &config.base_prefix, root), &config);
    check(PyConfig_SetBytesString(&config, &config.base_exec_prefix, root), &config);
    wchar_t *zip_wide = Py_DecodeLocale(zip, NULL), *dyn_wide = Py_DecodeLocale(dyn, NULL);
    if (!zip_wide || !dyn_wide) { PyConfig_Clear(&config); return 78; }
    check(PyWideStringList_Append(&config.module_search_paths, zip_wide), &config);
    check(PyWideStringList_Append(&config.module_search_paths, dyn_wide), &config);
    PyMem_RawFree(zip_wide); PyMem_RawFree(dyn_wide);
    config.module_search_paths_set = 1;
    check(Py_InitializeFromConfig(&config), &config);
    PyConfig_Clear(&config);
    return Py_RunMain();
}
