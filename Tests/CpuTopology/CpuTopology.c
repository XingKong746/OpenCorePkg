/** @file
  Host regression adapter for the actual CPU topology patch implementation.
  SPDX-License-Identifier: BSD-3-Clause
**/

#ifndef TEST_CPU_SOURCE
#define TEST_CPU_SOURCE  "../../Library/OcAppleKernelLib/CpuidPatches.c"
#endif
#include TEST_CPU_SOURCE

// Only platform memory operations and the Mach-O symbol binding are adapted.
// The CPU patch implementation and masked byte scanner are production code.
#include "../../Library/OcMiscLib/DataPatcher.c"
#include "../../Library/OcAppleKernelLib/KernelVersion.c"

STATIC UINT32  mSymbolOffset;
STATIC UINT32  mSymbolLookups;

MACH_HEADER_ANY *
MachoGetMachHeader (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  return Context->MachHeader;
}

UINT32
MachoGetInnerSize (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  return Context->InnerSize;
}

EFI_STATUS
PatcherGetSymbolAddressValue (
  IN OUT PATCHER_CONTEXT  *Context,
  IN CONST CHAR8          *Symbol,
  OUT UINT8               **Address,
  OUT UINT64              *Value
  )
{
  ++mSymbolLookups;
  return EFI_NOT_FOUND;
}

EFI_STATUS
PatcherGetSymbolAddress (
  IN OUT PATCHER_CONTEXT  *Context,
  IN CONST CHAR8          *Symbol,
  OUT UINT8               **Address
  )
{
  ++mSymbolLookups;
  return EFI_NOT_FOUND;
}

EFI_STATUS
PatcherGetSymbolValue (
  IN OUT PATCHER_CONTEXT  *Context,
  IN CONST CHAR8          *Symbol,
  OUT UINT64              *Value
  )
{
  ++mSymbolLookups;
  return EFI_NOT_FOUND;
}

VOID *EFIAPI
CopyMem (
  OUT VOID       *Destination,
  IN CONST VOID  *Source,
  IN UINTN       Length
  )
{
  UINT8        *Dst = Destination;
  CONST UINT8  *Src = Source;

  for (UINTN Index = 0; Index < Length; ++Index) {
    Dst[Index] = Src[Index];
  }

  return Destination;
}

VOID *EFIAPI
SetMem (
  OUT VOID  *Buffer,
  IN UINTN  Length,
  IN UINT8  Value
  )
{
  UINT8  *Data = Buffer;

  for (UINTN Index = 0; Index < Length; ++Index) {
    Data[Index] = Value;
  }

  return Buffer;
}

VOID *EFIAPI
ZeroMem (
  OUT VOID  *Buffer,
  IN UINTN  Length
  )
{
  return SetMem (Buffer, Length, 0);
}

EFI_STATUS
PatcherApplyGenericPatch (
  IN OUT PATCHER_CONTEXT    *Context,
  IN PATCHER_GENERIC_PATCH  *Patch
  )
{
  UINT8   *Base = Context->MachContext.FileData;
  UINT32  Size  = Context->MachContext.FileSize;

  if (Patch->Base != NULL) {
    // Every symbol-based patch used by this helper is based at _cpuid_set_info.
    CONST CHAR8  *Expected = "_cpuid_set_info";
    UINTN        Index     = 0;
    while (Expected[Index] == Patch->Base[Index] && Expected[Index] != '\0') {
      ++Index;
    }

    if ((Expected[Index] != Patch->Base[Index]) || (mSymbolOffset >= Size)) {
      return EFI_NOT_FOUND;
    }

    Base += mSymbolOffset;
    Size -= mSymbolOffset;
  }

  if ((Patch->Limit != 0) && (Patch->Limit < Size)) {
    Size = Patch->Limit;
  }

  return ApplyPatch (
           Patch->Find,
           Patch->Mask,
           Patch->Size,
           Patch->Replace,
           Patch->ReplaceMask,
           Base,
           Size,
           Patch->Count,
           Patch->Skip
           ) != 0
    ? EFI_SUCCESS : EFI_NOT_FOUND;
}

#if defined (_WIN32)
#define TEST_EXPORT  __declspec(dllexport)
#else
#define TEST_EXPORT  __attribute__((visibility("default")))
#endif

TEST_EXPORT
UINT64
TestApplyTopology (
  UINT8   *Buffer,
  UINT32  Size,
  UINT32  SymbolOffset,
  UINT16  Cores,
  UINT16  Threads,
  UINT32  Ebx,
  UINT32  Edx,
  UINT32  Version
  )
{
  PATCHER_CONTEXT  Context;
  OC_CPU_INFO      Cpu;

  ZeroMem (&Context, sizeof (Context));
  ZeroMem (&Cpu, sizeof (Cpu));
  Context.MachContext.FileData = Buffer;
  Context.MachContext.FileSize = Size;
  Cpu.CoreCount                = Cores;
  Cpu.ThreadCount              = Threads;
  Cpu.CpuidVerEbx.Uint32       = Ebx;
  Cpu.CpuidVerEdx.Uint32       = Edx;
  mSymbolOffset                = SymbolOffset;
  return PatchProvideCurrentCpuInfoMSR35h (&Context, &Cpu, Version, Ebx, Edx);
}

TEST_EXPORT
UINT64
TestFullCpuFailure (
  UINT8   *Buffer,
  UINT32  Size,
  UINT16  Cores,
  UINT16  Threads,
  UINT32  Ebx,
  UINT32  Edx,
  UINT32  *Lookups
  )
{
  PATCHER_CONTEXT  Context;
  OC_CPU_INFO      Cpu;
  EFI_STATUS       Status;

  ZeroMem (&Context, sizeof (Context));
  ZeroMem (&Cpu, sizeof (Cpu));
  Context.MachContext.FileData   = Buffer;
  Context.MachContext.FileSize   = Size;
  Context.MachContext.MachHeader = (MACH_HEADER_ANY *)Buffer;
  Context.MachContext.InnerSize  = Size;
  Cpu.CoreCount                  = Cores;
  Cpu.ThreadCount                = Threads;
  mSymbolOffset                  = 0;
  mSymbolLookups                 = 0;
  Status                         = PatchProvideCurrentCpuInfo (&Context, &Cpu, 240600, Ebx, Edx);
  *Lookups                       = mSymbolLookups;
  return Status;
}
