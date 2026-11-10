/** @file
  Exercise CPUID emulation gating in the real kernel patch caller.
  SPDX-License-Identifier: BSD-3-Clause
**/

#include <Base.h>
volatile UINT32  _gPcd_BinaryPatch_PcdSerialRegisterStride = 1;
#define OcKernelApplyPatches  __attribute__((always_inline)) OcKernelApplyPatches
#ifndef TEST_CALLER_SOURCE
#define TEST_CALLER_SOURCE  "../../Library/OcMainLib/OpenCoreKernelPatch.c"
#endif
#include TEST_CALLER_SOURCE
#undef OcKernelApplyPatches
#include "../../Library/OcAppleKernelLib/KernelVersion.c"

STATIC UINT32      *mResult;
STATIC EFI_STATUS  mCpuidStatus;

EFI_STATUS
KernelApplyQuirk (
  IN KERNEL_QUIRK_NAME    Quirk,
  IN OUT PATCHER_CONTEXT  *Context,
  IN UINT32               Version
  )
{
  mResult[0] = 0xDEAD;
  return EFI_UNSUPPORTED;
}

UINTN
GetSerialRegisterBase (
  VOID
  )
{
  mResult[0] = 0xDEAD;
  return 0;
}

INTN EFIAPI
AsciiStrCmp (
  IN CONST CHAR8  *First,
  IN CONST CHAR8  *Second
  )
{
  while (*First != '\0' && *First == *Second) {
    ++First;
    ++Second;
  }

  return (UINT8)*First - (UINT8)*Second;
}

VOID
PatchSetPciSerialDevice (
  IN UINTN   Base,
  IN UINT32  Stride
  )
{
  mResult[0] = 0xDEAD;
}

EFI_STATUS
PatcherApplyGenericPatch (
  IN OUT PATCHER_CONTEXT    *Context,
  IN PATCHER_GENERIC_PATCH  *Patch
  )
{
  // A fixture has no user patches. Entering this path must fail the test.
  mResult[0] = 0xDEAD;
  return EFI_UNSUPPORTED;
}

VOID *EFIAPI
ZeroMem (
  OUT VOID  *Buffer,
  IN UINTN  Length
  )
{
  UINT8  *Data = Buffer;

  for (UINTN Index = 0; Index < Length; ++Index) {
    Data[Index] = 0;
  }

  return Buffer;
}

EFI_STATUS
PatcherInitContextFromBuffer (
  OUT PATCHER_CONTEXT  *Context,
  IN UINT8             *Buffer,
  IN UINT32            Size,
  IN BOOLEAN           Is32Bit
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
PatchKernelCpuId (
  IN OUT PATCHER_CONTEXT  *Context,
  IN OC_CPU_INFO          *Cpu,
  IN UINT32               *Data,
  IN UINT32               *Mask,
  IN UINT32               Version
  )
{
  ++mResult[3];
  return mCpuidStatus;
}

EFI_STATUS
PatchProvideCurrentCpuInfo (
  IN OUT PATCHER_CONTEXT  *Context,
  IN OC_CPU_INFO          *Cpu,
  IN UINT32               Version,
  IN UINT32               Ebx,
  IN UINT32               Edx
  )
{
  ++mResult[0];
  mResult[1] = Ebx;
  mResult[2] = Edx;
  return EFI_SUCCESS;
}

__declspec(dllexport)
VOID
TestCaller (
  UINT32  Ebx,
  UINT32  Edx,
  UINT32  DataEbx,
  UINT32  MaskEbx,
  UINT32  DataEdx,
  UINT32  MaskEdx,
  UINT32  Version,
  CHAR8   *Min,
  CHAR8   *Max,
  UINT32  Active,
  UINT32  Fail,
  UINT32  *Result
  )
{
  STATIC OC_GLOBAL_CONFIG  Config;
  OC_CPU_INFO              Cpu;
  UINT8                    Kernel[1];

  ZeroMem (&Config, sizeof (Config));
  ZeroMem (&Cpu, sizeof (Cpu));
  ZeroMem (Result, sizeof (UINT32) * 5);
  mResult                                    = Result;
  mCpuidStatus                               = Fail ? EFI_NOT_FOUND : EFI_SUCCESS;
  Config.Kernel.Quirks.ProvideCurrentCpuInfo = TRUE;
  Config.Kernel.Emulate.Cpuid1Data[0]        = Active ? 0x306A9 : 0;
  Config.Kernel.Emulate.Cpuid1Data[1]        = DataEbx;
  Config.Kernel.Emulate.Cpuid1Mask[1]        = MaskEbx;
  Config.Kernel.Emulate.Cpuid1Data[3]        = DataEdx;
  Config.Kernel.Emulate.Cpuid1Mask[3]        = MaskEdx;
  Config.Kernel.Emulate.MinKernel.DynValue   = Min;
  Config.Kernel.Emulate.MaxKernel.DynValue   = Max;
  Cpu.CpuidVerEbx.Uint32                     = Ebx;
  Cpu.CpuidVerEdx.Uint32                     = Edx;
  OcKernelApplyPatches (&Config, &Cpu, Version, FALSE, CacheTypePrelinked, NULL, Kernel, sizeof (Kernel));
  Result[4] = Cpu.CpuidVerEbx.Uint32;
}
