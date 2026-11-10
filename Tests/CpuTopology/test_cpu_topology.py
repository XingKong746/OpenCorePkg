"""Run real CPU patch C code against bounded, hand-authored instruction fixtures.

Requires Python 3, Clang/lld and matching EDK headers. No boot, disk access or
external Python dependencies. The adapter replaces Mach-O symbol resolution with
a supplied fixture offset; it uses the production CPU helper and ApplyPatch.
"""
import argparse
import ctypes
from pathlib import Path
import struct
import subprocess
import sys
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--edk', required=True, type=Path)
parser.add_argument('--clang', required=True, type=Path)
parser.add_argument('--out', required=True, type=Path)
parser.add_argument('--cpu-source', type=Path, help='Source overlay for mutation checks')
parser.add_argument('--caller-source', type=Path, help='Source overlay for mutation checks')
args, remainder = parser.parse_known_args()
repo = Path(__file__).resolve().parents[2]
args.out.mkdir(parents=True, exist_ok=True)
flags = ['-O1', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
         '-fshort-wchar', '-ffunction-sections', '-fdata-sections',
         '-DMDEPKG_NDEBUG', '-DOC_TARGET_DEBUG', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter']
includes = [args.edk / 'MdePkg/Include', args.edk / 'MdePkg/Include/X64',
            args.edk / 'MdeModulePkg/Include', args.edk / 'UefiCpuPkg/Include']
includes += [repo / 'Include' / name for name in
             ['Acidanthera', 'Apple', 'Apple/X64', 'Duet', 'Generic', 'Intel', 'Microsoft', 'Nvidia']]
flags += [item for path in includes for item in ['-I', str(path)]]
if args.cpu_source:
    flags.append('-DTEST_CPU_SOURCE="' + args.cpu_source.resolve().as_posix() + '"')
if args.caller_source:
    flags.append('-DTEST_CALLER_SOURCE="' + args.caller_source.resolve().as_posix() + '"')

def build_adapter(stem, public_api):
    obj = args.out / (stem + '.obj')
    bitcode = args.out / (stem + '.bc')
    filtered = args.out / (stem + '.filtered.bc')
    library = args.out / (stem + '.dll')
    cmd = [str(args.clang), '--target=x86_64-pc-windows-msvc', *flags,
           '-emit-llvm', '-c', str(Path(__file__).with_name(stem + '.c')), '-o', str(bitcode)]
    subprocess.run(cmd, check=True)
    subprocess.run([str(args.clang.with_name('opt.exe')), '-passes=internalize,globaldce,default<O3>',
                    '-internalize-public-api-list=' + public_api, str(bitcode), '-o', str(filtered)], check=True)
    subprocess.run([str(args.clang), '--target=x86_64-pc-windows-msvc', '-c', str(filtered),
                    '-o', str(obj)], check=True)
    subprocess.run([str(args.clang.with_name('lld-link.exe')), '/dll', '/noentry',
                    '/nodefaultlib', '/opt:ref', '/opt:icf', f'/out:{library}', str(obj)], check=True)
    return ctypes.CDLL(str(library))

lib = build_adapter('CpuTopology', 'TestApplyTopology,TestFullCpuFailure')
apply = lib.TestApplyTopology
apply.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.c_uint32,
                  ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint32,
                  ctypes.c_uint32, ctypes.c_uint32]
apply.restype = ctypes.c_uint64
full_failure = lib.TestFullCpuFailure
full_failure.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32,
                        ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint32,
                        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
full_failure.restype = ctypes.c_uint64
caller_lib = build_adapter('CpuTopologyCaller', 'TestCaller')
caller = caller_lib.TestCaller
caller.argtypes = [ctypes.c_uint32] * 7 + [ctypes.c_char_p, ctypes.c_char_p] + [ctypes.c_uint32] * 2 + [ctypes.POINTER(ctypes.c_uint32)]
caller.restype = None
INVALID = 0x8000000000000002
NOT_FOUND = 0x800000000000000E
HTT = 1 << 28
PATTERNS = {'v1': 'c1e81affc089', 'v1_5': 'c1ea1affc289',
            'v2_eax': 'c1e81a83c00189', 'v2_edx': 'c1ea1a83c20189'}

def fixture(variant='v1_5', version=240600, cores=8, threads=12,
            capacity=64, htt=True, msr=True):
    data = bytearray(b'\xcc' * 128)
    if msr:
        data[16:23] = data[32:39] = bytes.fromhex('b9350000000f32')
    if variant in PATTERNS:
        pattern = bytes.fromhex(PATTERNS[variant])
        data[64:64 + len(pattern)] = pattern
    native = (ctypes.c_ubyte * len(data)).from_buffer(data)
    status = apply(native, len(data), 0, cores, threads, capacity << 16,
                   HTT if htt else 0, version)
    return status, data

class CpuTopologyTests(unittest.TestCase):
    def check_capacity(self, variant, capacity, version=240600):
        status, data = fixture(variant=variant, capacity=capacity, version=version)
        self.assertEqual(status, 0, (variant, capacity, hex(status)))
        # Both MSR35h reads must represent the intended flattened 12/12 topology.
        self.assertEqual(data[16:23], bytes.fromhex('b80c000c0031d2'))
        self.assertEqual(data[32:39], bytes.fromhex('b80c000c0031d2'))
        if variant.startswith('v2'):
            reg = 'e8' if variant.endswith('eax') else 'ea'
            low = 'b0' if variant.endswith('eax') else 'b2'
            expected = bytes.fromhex('c1' + reg + '1a90' + low) + bytes([capacity, 0x89])
        else:
            expected = bytes([0xb8 if variant == 'v1' else 0xba]) + struct.pack('<I', capacity) + b'\x89'
        self.assertEqual(data[64:64 + len(expected)], expected)
        # XNU's logical/core capacity ratio must be one, rather than zero.
        actual = data[69] if variant.startswith('v2') else struct.unpack_from('<I', data, 65)[0]
        self.assertEqual(capacity // actual, 1)

    def test_sequoia_64_capacity_v1_5(self):
        self.check_capacity('v1_5', 64)

    def test_128_capacity(self):
        self.check_capacity('v1_5', 128)

    def test_repeated_calls_do_not_reuse_previous_capacity(self):
        for value in [64, 128, 32, 255, 64, 12]:
            with self.subTest(capacity=value):
                self.check_capacity('v1_5', value)

    def test_older_kernel_variants(self):
        for variant in ['v1', 'v1_5']:
            with self.subTest(variant=variant):
                self.check_capacity(variant, 64, 200600)

    def test_v2_both_registers_and_full_byte_immediate(self):
        for variant in ['v2_eax', 'v2_edx']:
            for capacity in [64, 128, 255]:
                with self.subTest(variant=variant, capacity=capacity):
                    self.check_capacity(variant, capacity)

    def test_invalid_capacity_is_rejected_before_modifying_msr(self):
        for capacity, htt in [(0, True), (8, True), (64, False)]:
            with self.subTest(capacity=capacity, htt=htt):
                status, data = fixture(capacity=capacity, htt=htt)
                self.assertEqual(status, INVALID)
                self.assertEqual(data[16:23], bytes.fromhex('b9350000000f32'))
                self.assertEqual(data[64:70], bytes.fromhex(PATTERNS['v1_5']))

    def test_invalid_enabled_counts_are_rejected(self):
        for cores, threads in [(0, 12), (8, 0), (12, 8)]:
            with self.subTest(cores=cores, threads=threads):
                status, data = fixture(cores=cores, threads=threads)
                self.assertEqual(status, INVALID)
                self.assertEqual(data[16:23], bytes.fromhex('b9350000000f32'))

    def test_symmetric_cpu_keeps_real_core_thread_count(self):
        status, data = fixture(cores=6, threads=12)
        self.assertEqual(status, 0)
        self.assertEqual(data[16:23], bytes.fromhex('b80c00060031d2'))
        self.assertEqual(data[64:70], bytes.fromhex(PATTERNS['v1_5']))

    def test_pre_mojave_is_untouched(self):
        status, data = fixture(version=170000)
        self.assertEqual(status, 0)
        self.assertEqual(data[16:23], bytes.fromhex('b9350000000f32'))
        self.assertEqual(data[64:70], bytes.fromhex(PATTERNS['v1_5']))

    def test_missing_capacity_pattern_remains_failure(self):
        status, data = fixture(variant='missing')
        self.assertEqual(status, NOT_FOUND)
        self.assertEqual(data[64:72], b'\xcc' * 8)

    def test_missing_msr_pattern_does_not_change_capacity(self):
        status, data = fixture(msr=False)
        self.assertEqual(status, NOT_FOUND)
        self.assertEqual(data[64:70], bytes.fromhex(PATTERNS['v1_5']))

    def test_topology_failure_preserves_status_without_tsc_lookup(self):
        for cores, capacity, expected in [(0, 64, INVALID), (8, 0, INVALID), (8, 64, NOT_FOUND)]:
            with self.subTest(cores=cores, capacity=capacity):
                native = (ctypes.c_ubyte * 0x4000)()
                lookups = ctypes.c_uint32(123)
                status = full_failure(native, len(native), cores, 12, capacity << 16, HTT, ctypes.byref(lookups))
                self.assertEqual(status, expected)
                self.assertEqual(lookups.value, 0)

class CpuTopologyCallerTests(unittest.TestCase):
    def call(self, data_ebx=0, mask_ebx=0, data_edx=0, mask_edx=0,
             version=240600, minimum=b'24.6.0', maximum=b'24.6.0', active=1, fail=0):
        result = (ctypes.c_uint32 * 5)()
        caller(0x11400800, HTT | 0x10, data_ebx, mask_ebx, data_edx, mask_edx,
               version, minimum, maximum, active, fail, result)
        return list(result)

    def test_successful_masked_override_reaches_cpu_info_patch(self):
        self.assertEqual(self.call(data_ebx=0xab800000, mask_ebx=0x00ff0000),
                         [1, 0x11800800, HTT | 0x10, 1, 0x11400800])

    def test_outside_emulation_version_range_uses_native_cpuid(self):
        for version in [240500, 240601]:
            with self.subTest(version=version):
                self.assertEqual(self.call(data_ebx=0x800000, mask_ebx=0xff0000, version=version),
                                 [1, 0x11400800, HTT | 0x10, 0, 0x11400800])

    def test_eax_only_emulation_preserves_capacity(self):
        self.assertEqual(self.call(), [1, 0x11400800, HTT | 0x10, 1, 0x11400800])

    def test_zero_data_does_not_activate_masks(self):
        self.assertEqual(self.call(active=0, mask_ebx=0xffffffff, mask_edx=0xffffffff),
                         [1, 0x11400800, HTT | 0x10, 0, 0x11400800])

    def test_htt_override_is_forwarded(self):
        self.assertEqual(self.call(mask_edx=HTT), [1, 0x11400800, 0x10, 1, 0x11400800])

    def test_partial_ebx_mask_preserves_unmasked_bits(self):
        self.assertEqual(self.call(mask_ebx=0x00400000),
                         [1, 0x11000800, HTT | 0x10, 1, 0x11400800])

    def test_failed_cpuid_patch_does_not_guess_effective_capacity(self):
        self.assertEqual(self.call(data_ebx=0x800000, mask_ebx=0xff0000, fail=1),
                         [0, 0, 0, 1, 0x11400800])

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remainder], verbosity=2)
