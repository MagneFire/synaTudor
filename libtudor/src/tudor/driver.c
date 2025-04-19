#include <unistd.h>

#include "internal.h"

DEFINE_GUID1(IID_IUnknown, 0x00000000, 0x0000, 0x0000, 0xc0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46);
DEFINE_GUID1(IID_IDriverEntry, 0x1BEC7499, 0x8881, 0x4F2B, 0xB0, 0x1C, 0xA1, 0xA9, 0x07, 0x30, 0x4A, 0xFC);
DEFINE_GUID1(GUID_DEVINTERFACE_BIOMETRIC_READER, 0xe2b5183a, 0x99ea, 0x4cc3, 0xad, 0x6b, 0x80, 0xca, 0x8d, 0x71, 0x5b, 0x80);
DEFINE_GUID1(SYNA_CLSID, 0x96710705, 0xb080, 0x4b29, 0xa3, 0xec, 0xb1, 0x69, 0x35, 0xae, 0x66, 0x3a);

extern uint8_t _binary_libtudor_synaAdvAdapter_dll_start, _binary_libtudor_synaAdvAdapter_dll_end;
//extern uint8_t _binary_libtudor_synaBscAdapter_dll_start, _binary_libtudor_synaBscAdapter_dll_end;
extern uint8_t _binary_libtudor_synaWudfBioUsb_dll_start, _binary_libtudor_synaWudfBioUsb_dll_end;

#define NUM_WINDRV_DLLS 2
struct windrv_dll tudor_windrv_dlls[] = {
    {
        .module = {
                .name = "synaAdvAdapter.dll",
                .cmdline = "synaAdvAdapter.dll",
                .environ = (const char*[]) { NULL }
        },
        .pe_image = &_binary_libtudor_synaAdvAdapter_dll_start, .pe_image_end = &_binary_libtudor_synaAdvAdapter_dll_end,
        .is_adapter = true, .is_driver = false
    },
//    {
//        .module = {
//            .name = "synaBscAdapter.dll",
//            .cmdline = "synaBscAdapter.dll",
//            .environ = (const char*[]) { NULL }
//        },
//        .pe_image = &_binary_libtudor_synaBscAdapter_dll_start, .pe_image_end = &_binary_libtudor_synaBscAdapter_dll_end,
//        .is_adapter = true, .is_driver = false
//    },
    {
        .module = {
            .name = "synaWudfBioUsb.dll",
            .cmdline = "synaWudfBioUsb.dll",
            .environ = (const char*[]) { NULL }
        },
        .pe_image = &_binary_libtudor_synaWudfBioUsb_dll_start, .pe_image_end = &_binary_libtudor_synaWudfBioUsb_dll_end,
        .is_adapter = false, .is_driver = true
    }
};

bool tudor_log_traces;

static struct winmodule ntdll_module = {
    .name = "ntdll.dll",
    .cmdline = "ntdll.dll",
    .environ = (const char*[]) { NULL }
};

#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3
typedef BOOL __winfnc (*api_DllMain)(HANDLE hinstDLL, int fdwReason, void *lpReserved);

struct windrv_dll *tudor_adapter_dll, *tudor_driver_dll;
WINBIO_SENSOR_INTERFACE *tudor_sensor_adapter;
WINBIO_ENGINE_INTERFACE *tudor_engine_adapter;

static DRIVER_OBJECT umdf_driver;
struct winwdf_driver *tudor_wdf_driver;

typedef struct IUnknown IUnknownVtbl;

typedef struct IUnknown {
    const IUnknownVtbl *lpVtbl;
} IUnknown;

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(IUnknown *This, REFIID riid, void **ppvObject);
    ULONG (*AddRef)(IUnknown *This);
    ULONG (*Release)(IUnknown *This);
};

typedef struct IClassFactoryVtbl IClassFactoryVtbl;

typedef struct IClassFactory {
    const IClassFactoryVtbl *lpVtbl;
} IClassFactory;

struct IClassFactoryVtbl {
    // HRESULT (*QueryInterface)(void **This, void **, void **ppvObject);
    // ULONG (*AddRef)(void **);
    // ULONG (*Release)(void **);
    HRESULT (*QueryInterface)(IClassFactory *This, REFIID riid, void **ppvObject);
    ULONG (*AddRef)(IClassFactory *This);
    ULONG (*Release)(IClassFactory *This);

    HRESULT (__cdecl *CreateInstance)(IClassFactory *This, IUnknown *pUnkOuter, REFIID riid, void **ppvObject);
    // HRESULT (__cdecl *CreateInstance)(void **, void **, void **, void **);
    HRESULT (*LockServer)(IClassFactory *This, BOOL fLock);
};

typedef void IWDFDriver;
typedef void IWDFDeviceInitialize;
typedef struct IDriverEntryVtbl IDriverEntryVtbl;

typedef struct IDriverEntry {
    const IDriverEntryVtbl *lpVtbl;
} IDriverEntry;

struct IDriverEntryVtbl {
    HRESULT (*QueryInterface)(IDriverEntry *This, REFIID riid, void **ppvObject);
    ULONG (*AddRef)(IDriverEntry *This);
    ULONG (*Release)(IDriverEntry *This);

    HRESULT (*OnInitialize)(IDriverEntry *This, IWDFDriver *pWdfDriver);
    HRESULT (*OnDeviceAdd)(IDriverEntry *This, IWDFDriver *pWdfDriver, IWDFDeviceInitialize *pWdfDeviceInit);
    void (*OnDeinitialize)(IDriverEntry *This, IWDFDriver *pWdfDriver);
};

typedef struct IObjectCleanupVtbl IObjectCleanupVtbl;

typedef struct IObjectCleanup
{
    struct IObjectCleanupVtbl *lpVtbl;
} IObjectCleanup;

typedef struct IWDFObjectVtbl IWDFObjectVtbl;

typedef struct IWDFObject
{
    struct IWDFObjectVtbl *lpVtbl;
} IWDFObject;

typedef struct IObjectCleanupVtbl
{
    HRESULT (*QueryInterface )(IObjectCleanup * This, REFIID riid, void **ppvObject);

    ULONG (*AddRef )(IObjectCleanup * This);

    ULONG (*Release )(IObjectCleanup * This);

    void (*OnCleanup )(IObjectCleanup * This, IWDFObject *pWdfObject);
} IObjectCleanupVtbl;


    typedef struct IWDFObjectVtbl
    {
        HRESULT (*QueryInterface )(IWDFObject * This, REFIID riid, void **ppvObject);
        
        ULONG (*AddRef )(IWDFObject * This);

        ULONG (*Release )(IWDFObject * This);
        HRESULT (*DeleteWdfObject )(IWDFObject * This);
        
        HRESULT (*AssignContext )(IWDFObject * This,IObjectCleanup *pCleanupCallback,void *pContext);
        
        HRESULT (*RetrieveContext )(IWDFObject * This,void **ppvContext);
        
        void (*AcquireLock )(IWDFObject * This);
        
        void (*ReleaseLock )(IWDFObject * This);
    } IWDFObjectVtbl;

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// typedef struct IWDFDriverVtbl IWDFDriverVtbl;
// typedef struct MyDriver MyDriver;
//
// struct IWDFDriverVtbl {
//     HRESULT (*QueryInterface)(MyDriver *, REFIID, void **);
//     ULONG (*AddRef)(MyDriver *);
//     ULONG (*Release)(MyDriver *);
//     HRESULT (*DeleteWdfObject)(MyDriver *);
//     HRESULT (*AssignContext)(MyDriver *, IObjectCleanup *, void *);
//     HRESULT (*RetrieveContext)(MyDriver *, void **);
//     void (*AcquireLock)(MyDriver *);
//     void (*ReleaseLock)(MyDriver *);
//     HRESULT (*CreateDevice)(MyDriver *, IWDFDeviceInitialize *, IUnknown *, IWDFDevice **);
//     HRESULT (*CreateWdfObject)(MyDriver *, IUnknown *, IWDFObject *, IWDFObject **);
//     HRESULT (*CreatePreallocatedWdfMemory)(MyDriver *, BYTE *, SIZE_T, IUnknown *, IWDFObject *, IWDFMemory **);
//     HRESULT (*CreateWdfMemory)(MyDriver *, SIZE_T, IUnknown *, IWDFObject *, IWDFMemory **);
//     BOOL (*IsVersionAvailable)(MyDriver *, UMDF_VERSION_DATA *);
//     HRESULT (*RetrieveVersionString)(MyDriver *, PWSTR, DWORD *);
// };
//
// struct MyDriver {
//     IWDFDriverVtbl *lpVtbl;
//     // Additional fields if necessary
// };

// HRESULT QueryInterface(MyDriver *self, REFIID riid, void **ppvObject) {
//     printf("QueryInterface\r\n");
//     return 0;
// }
//
// ULONG AddRef(MyDriver *self) {
//     printf("AddRef\r\n");
//     return 0;
// }
//
// ULONG Release(MyDriver *self) {
//     printf("MyDriver::Release\r\n");
//     return 0;
// }
//
// HRESULT DeleteWdfObject(MyDriver *self) {
//     printf("DeleteWdfObject\r\n");
//     return 0;
// }
//
// HRESULT AssignContext(MyDriver *self, IObjectCleanup *pCleanupCallback, void *pContext) {
//     printf("AssignContext\r\n");
//     return 0;
// }
//
// HRESULT RetrieveContext(MyDriver *self, void **ppvContext) {
//     printf("RetrieveContext\r\n");
//     return 0;
// }
//
// void AcquireLock(MyDriver *self) {
//     printf("AcquireLock\r\n");
// }
//
// void ReleaseLock(MyDriver *self) {
//     printf("ReleaseLock\r\n");
// }
//
// HRESULT CreateDevice(MyDriver *self, IWDFDeviceInitialize *pDeviceInit, IUnknown *pCallbackInterface, IWDFDevice **ppDevice) {
//     printf("CreateDevice\r\n");
//     return 0;
// }
//
// HRESULT CreateWdfObject(MyDriver *self, IUnknown *pCallbackInterface, IWDFObject *pParentObject, IWDFObject **ppWdfObject) {
//     printf("CreateWdfObject\r\n");
//     return 0;
// }
//
// HRESULT CreatePreallocatedWdfMemory(MyDriver *self, BYTE *pBuff, SIZE_T BufferSize, IUnknown *pCallbackInterface, IWDFObject *pParentObject, IWDFMemory **ppWdfMemory) {
//     printf("CreatePreallocatedWdfMemory\r\n");
//     return 0;
// }
//
// HRESULT CreateWdfMemory(MyDriver *self, SIZE_T BufferSize, IUnknown *pCallbackInterface, IWDFObject *pParentObject, IWDFMemory **ppWdfMemory) {
//     printf("CreateWdfMemory\r\n");
//     return 0;
// }
//
// BOOL IsVersionAvailable(MyDriver *self, UMDF_VERSION_DATA *pMinimumVersion) {
//     printf("IsVersionAvailable\r\n");
//     return true;
// }
//
// HRESULT RetrieveVersionString(MyDriver *self, PWSTR pVersion, DWORD *pdwVersionLength) {
//     printf("RetrieveVersionString\r\n");
//     return 0;
// }
//
// static IWDFDriverVtbl MyDriver_Vtbl = {
//     QueryInterface,
//     AddRef,
//     Release,
//     DeleteWdfObject,
//     AssignContext,
//     RetrieveContext,
//     AcquireLock,
//     ReleaseLock,
//     CreateDevice,
//     CreateWdfObject,
//     CreatePreallocatedWdfMemory,
//     CreateWdfMemory,
//     IsVersionAvailable,
//     RetrieveVersionString
// };
//
// void MyDriver_Init(MyDriver *driver) {
//     driver->lpVtbl = &MyDriver_Vtbl;
// }


bool tudor_init()
{
    //Register dummy modules
    winmodule_register(&ntdll_module);

    if(tudor_log_traces) {
        //Register trace messages
        winlog_register_trace_msg(DEFINE_GUID(58f95b1a, 8efd, 39f0, 5626, 3e620b587295), 0x0c, "%s<X> checkpoint hit <X>");
        winlog_register_trace_msg(DEFINE_GUID(58f95b1a, 8efd, 39f0, 5626, 3e620b587295), 0x0d, "%s<X> checkpoint hit <X>");

        winlog_register_trace_msg(DEFINE_GUID(824d7f8b, e993, 3db5, 6a1a, 91a0d317b75a), 0x0a, "%s-> %s");
        winlog_register_trace_msg(DEFINE_GUID(824d7f8b, e993, 3db5, 6a1a, 91a0d317b75a), 0x0b, "%s<- %s");
        winlog_register_trace_msg(DEFINE_GUID(824d7f8b, e993, 3db5, 6a1a, 91a0d317b75a), 0x0c, "%s<- %s [0x%x]");
        winlog_register_trace_msg(DEFINE_GUID(824d7f8b, e993, 3db5, 6a1a, 91a0d317b75a), 0x0d, "%s-> %s");
        winlog_register_trace_msg(DEFINE_GUID(824d7f8b, e993, 3db5, 6a1a, 91a0d317b75a), 0x0f, "%s<- %s [0x%x]");

        winlog_register_trace_msg(DEFINE_GUID(2c18840b, 2ee0, 377e, f168, 1552bbd307c4), 0x0a, "VFM LOG | %s\033[1A");
    }

    //Set registry handler
    winreg_set_handler(tudor_reg_handler, NULL);

    //Load driver DLLs
    tudor_adapter_dll = tudor_driver_dll = NULL;
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];
        if(!load_dll(&dll->image, dll->module.name, dll->pe_image, dll->pe_image_end - dll->pe_image)) {
            log_error("Error loading driver DLL!");
            return false;
        }
        winmodule_register(&dll->module);
        log_info("Loaded driver DLL '%s' [%ld bytes]", dll->module.name, dll->pe_image_end - dll->pe_image);

        if(dll->is_adapter) tudor_adapter_dll = dll;
        if(dll->is_driver) tudor_driver_dll = dll;
    }
    if(!tudor_adapter_dll) abort();
    if(!tudor_driver_dll) abort();

    //Initialize driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];

        if(dll->image.entry_point) {
            log_info("Initializing driver DLL '%s'...", dll->module.name);
            winmodule_set_cur(&dll->module);
            if(!((api_DllMain) dll->image.entry_point)(dll->module.handle, DLL_PROCESS_ATTACH, NULL)) {
                log_error("Error initializing driver DLL '%s'!", dll->module.name);
                return false;
            }
        }
    }

    //Call UMDF driver entry function
    init_winwdf();
    winmodule_set_cur(&tudor_driver_dll->module);

    char16_t *reg_path_wstr = winstr_from_str("HKEY_LOCAL_MACHINE\\Tudor\\Driver");
    // UNICODE_STRING reg_path = {
    //     .Length = winstr_len(reg_path_wstr)+1,
    //     .MaximumLength = winstr_len(reg_path_wstr)+1,
    //     .Buffer = reg_path_wstr
    // };

    // NTSTATUS status;
    // if((status = ((api_FxDriverEntryUm) find_dll_export(&tudor_driver_dll->image, "FxDriverEntryUm"))(&wdf_loader, NULL, &umdf_driver, &reg_path)) != 0) {
    //     log_error("Error in UMDF driver 2.0 entry function: 0x%x!", status);
    //     return false;
    // }

    HRESULT result;
    // CLSID class_id = DEFINE_GUID(96710705, B080, 4B29, A3EC, B16935AE663A);
    // IID idriver_entry_id = DEFINE_GUID(1bec7499, 8881, 4f2b, b01c, a1a907304afc);
    // IID iuknown_id = DEFINE_GUID(00000000, 0000, 0000, C000, 000000000046);
    // IID biometric_reader_id = DEFINE_GUID(E2B5183A, 99EA, 4cc3, AD6B, 80CA8D715B80);

    api_DllGetClassObject dll_get_class_object = find_dll_export(&tudor_driver_dll->image, "DllGetClassObject");

    IClassFactory *class_factory = 0;
    log_warn("Getting class object");

    if((result = dll_get_class_object((REFCLSID)&SYNA_CLSID, (REFIID)&IID_IUnknown, &class_factory)) != 0) {
        log_error("Error in UMDF driver 1.x entry function: 0x%x!", result);
        return false;
    }
    if(!class_factory) {
        log_error("Class factory is invalid");
        return false;
    }
    void *biometric_reader = 0;
    // Obtain biometric instance to avoid CLASSFACTORY_E_FIRST/CLASS_E_NOAGGREGATION errors
    // GUID_DEVINTERFACE_BIOMETRIC_READER
    result = dll_get_class_object((GUID*)&GUID_DEVINTERFACE_BIOMETRIC_READER, (REFIID)&IID_IUnknown, &biometric_reader);
    if (result != 0) {
        log_error("Error GUID_DEVINTERFACE_BIOMETRIC_READER! 0x%x! %p", result, biometric_reader);
    }

    // IDriverEntry *driver_entry = 0;
    void *driver_entry = 0;
    // IID_IDriverEntry
    // idriver_entry_id
    // result = class_factory->lpVtbl->CreateInstance(class_factory, NULL, (REFIID)&IID_IDriverEntry, (PVOID *)&driver_entry);

    result = class_factory->lpVtbl->QueryInterface(&driver_entry, &driver_entry, &driver_entry);
    if (result != 0) {
        log_error("Error QueryInterface! 0x%x!", result);
        return false;
    }
    result = class_factory->lpVtbl->AddRef(&driver_entry);
    if (result != 0) {
        log_error("Error AddRef! 0x%x!", result);
        return false;
    }
    result = class_factory->lpVtbl->Release(&driver_entry);
    if (result != 0) {
        log_error("Error Release! 0x%x!", result);
        return false;
    }
    result = class_factory->lpVtbl->CreateInstance(&driver_entry, &driver_entry, &driver_entry, &driver_entry);
    if (result != 0) {
        log_error("Error CreateInstance! 0x%x!", result);
        return false;
    }


    // MyDriver driver;
    //
    // MyDriver_Init(&driver);
    // void * driver = 0;
    // driver_entry->lpVtbl->OnInitialize(driver_entry, &driver);
    // void * wdfdriver = 0;
    // void * wdfdeviceinit = 0;
    // driver_entry->lpVtbl->OnDeviceAdd(driver_entry, wdfdriver, wdfdeviceinit);

    free(reg_path_wstr);

    if(!(tudor_wdf_driver = winwdf_get_driver(&wdf_globals))) {
        log_error("UMDF entry function didn't create a WDF driver!");
        return false;
    }

    //Query WINBIO interfaces
    winmodule_set_cur(&tudor_adapter_dll->module);

    HRESULT hres;
    if((hres = ((api_WbioQuerySensorInterface) find_dll_export(&tudor_adapter_dll->image, "WbioQuerySensorInterface"))(&tudor_sensor_adapter)) != 0) {
        log_error("Error querying sensor interface: 0x%x!", hres);
        return false;
    }
    if((hres = ((api_WbioQueryEngineInterface) find_dll_export(&tudor_adapter_dll->image, "WbioQueryEngineInterface"))(&tudor_engine_adapter)) != 0) {
        log_error("Error querying engine interface: 0x%x!", hres);
        return false;
    }

    return true;
}

bool tudor_shutdown() {
    //Unload the driver
    winmodule_set_cur(&tudor_driver_dll->module);

    log_debug("Unloading WDF driver...");
    winwdf_unload_driver(tudor_wdf_driver);
    
    if(umdf_driver.DriverUnload) {
        log_debug("Unloading UMDF driver...");
        umdf_driver.DriverUnload(&umdf_driver);
    }
    umdf_driver = (DRIVER_OBJECT) {0};

    //Uninitialize driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];

        if(dll->image.entry_point) {
            log_info("Uninitializing driver DLL '%s'...", dll->module.name);
            winmodule_set_cur(&dll->module);
            if(!((api_DllMain) dll->image.entry_point)(dll->module.handle, DLL_PROCESS_DETACH, NULL)) {
                log_error("Error uninitializing driver DLL '%s'!", dll->module.name);
                return false;
            }
        }
        winmodule_unregister(&dll->module);
    }

    //Destroy driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) destroy_dll(&tudor_windrv_dlls[i].image);

    //Unregister dummy modules
    winmodule_unregister(&ntdll_module);

    return true;
}
