#include "common/common.h"
#include <unknwn.h>
// #include <windows.h>

const CLSID CLSID_BlankDcomObject = {
    0x11111111,
    0x2222,
    0x3333,
    {0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77}};
const IID IID_IBlankInterface = {
    0x88888888,
    0x9999,
    0xaaaa,
    {0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee}};

typedef struct IMyInterfaceVtbl {
  // IUnknown methods (Required for all COM interfaces)
  HRESULT(STDMETHODCALLTYPE *QueryInterface)(void *This, REFIID riid,
                                             void **ppvObject);
  ULONG(STDMETHODCALLTYPE *AddRef)(void *This);
  ULONG(STDMETHODCALLTYPE *Release)(void *This);

} IMyInterfaceVtbl;

typedef struct IMyInterface {
  IMyInterfaceVtbl *lpVtbl;
} IMyInterface;

typedef struct ChocoObject {
  IMyInterfaceVtbl *lpVtbl;
  LONG refCount;
} ChocoObject;
extern IMyInterfaceVtbl ChocoVtbl;

NTSTATUS ChocoPotato();
